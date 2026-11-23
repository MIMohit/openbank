// Bench API executor: go-chi v5 on net/http (CONTRACT section 3).
//
// Handler chain, outermost first:
//
//	logMW                      records raw method/target, writes the JSONL line after the handler
//	handlers.HTTPMethodOverrideHandler   gorilla/handlers v1.5.2, only when OVERRIDE=on
//	chi.Mux                    routes; /api/v2 is a chi sub-router attached with r.Mount
//
// The chi.Mux is passed to http.Server directly, so net/http.ServeMux path cleaning does NOT apply.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/handlers"
)

var (
	framework   = envOr("FRAMEWORK_TAG", "go-chi")
	override    = strings.ToLower(envOr("OVERRIDE", "off")) == "on"
	// ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes). Off => :latest.
	routesV2 = strings.ToLower(envOr("ROUTES", "off")) == "v2"
	verifyMode  = strings.ToLower(envOr("VERIFY_MODE", "off"))
	verifierURL = envOr("VERIFIER_URL", "http://verifier:9100/authz/orig")
	logPath     = envOr("LOG_PATH", "/logs/executor.jsonl")
	trustPfx    = []string{"x-forwarded-", "x-original-", "x-verified-", "x-client-cert",
		"client-cert", "x-forwarded-client-cert", "x-auth-"}
	logMu      sync.Mutex
	httpClient = &http.Client{Timeout: 3 * time.Second}
)

func envOr(k, d string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return d
}

type benchInfo struct {
	OpID          string
	RouteTemplate *string
	PathParams    map[string]string
	Denied        bool
	RawMethod     string
	RawTarget     string
}

type ctxKey struct{}

func info(r *http.Request) *benchInfo { return r.Context().Value(ctxKey{}).(*benchInfo) }

func jtiFromDPoP(v string) any {
	if v == "" {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil
	}
	if s, ok := claims["jti"].(string); ok {
		return s
	}
	return nil
}

// quote mirrors Python urllib.parse.quote(v, safe="-._~!$&'()*+,;=:@")
func quote(v string) string {
	const safe = "-._~!$&'()*+,;=:@"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(string("0123456789abcdef"[c>>4])+string("0123456789abcdef"[c&15])))
		}
	}
	return b.String()
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

func writeLog(rec map[string]any) {
	line, _ := json.Marshal(rec)
	logMu.Lock()
	defer logMu.Unlock()
	os.Stdout.Write(append(line, '\n'))
	if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		f.Write(append(line, '\n'))
		f.Close()
	}
}

func logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bi := &benchInfo{OpID: "NOT_FOUND", PathParams: map[string]string{}, RawMethod: r.Method, RawTarget: r.RequestURI}
		trust := map[string]string{}
		for k, vs := range r.Header {
			lk := strings.ToLower(k)
			for _, p := range trustPfx {
				if strings.HasPrefix(lk, p) {
					trust[lk] = strings.Join(vs, ", ")
					break
				}
			}
		}
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, bi))
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = 200
		}
		var tmpl any
		if bi.RouteTemplate != nil {
			tmpl = *bi.RouteTemplate
		}
		writeLog(map[string]any{
			"ts":               time.Now().UTC().Format(time.RFC3339Nano),
			"framework":        framework,
			"jti":              jtiFromDPoP(r.Header.Get("DPoP")),
			"op_id":            bi.OpID,
			"route_template":   tmpl,
			"raw_method":       bi.RawMethod,
			"effective_method": r.Method, // same *Request the override handler mutated
			"raw_target":       bi.RawTarget,
			"path_params":      bi.PathParams,
			"query":            r.URL.RawQuery,
			"trust_headers":    trust,
			"denied":           bi.Denied,
			"status":           sw.status,
		})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func callVerifier(method, uri, host string, r *http.Request) bool {
	req, err := http.NewRequest(http.MethodGet, verifierURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Original-Method", method)
	req.Header.Set("X-Original-URI", uri)
	req.Header.Set("X-Original-Host", host)
	if v, ok := r.Header["Authorization"]; ok {
		req.Header["Authorization"] = v
	}
	if v, ok := r.Header["Dpop"]; ok {
		req.Header["Dpop"] = v
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false // fail closed
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func respond(w http.ResponseWriter, r *http.Request, opID, template string, names ...string) {
	params := map[string]string{}
	canon := template
	for _, n := range names {
		v := chi.URLParam(r, n) // raw (still percent-encoded) when chi routed on r.URL.RawPath
		params[n] = v
		dec := v
		if r.URL.RawPath != "" {
			if d, err := url.PathUnescape(v); err == nil {
				dec = d
			}
		}
		canon = strings.Replace(canon, "{"+n+"}", quote(dec), 1)
	}
	t := template
	finish(w, r, opID, &t, params, canon)
}

// finish records the op, runs the verifier (if enabled) and writes the response. Shared by the
// template-based respond() and the catch-all handler, which supplies its own param map.
func finish(w http.ResponseWriter, r *http.Request, opID string, template *string,
	params map[string]string, canon string) {
	bi := info(r)
	bi.OpID, bi.RouteTemplate, bi.PathParams = opID, template, params
	if verifyMode != "off" {
		vm, vu := bi.RawMethod, bi.RawTarget
		if verifyMode == "origin-routed" {
			vm, vu = r.Method, canon
		}
		if !callVerifier(vm, vu, r.Host, r) {
			bi.Denied = true
			writeJSON(w, 401, map[string]any{"op_id": opID, "framework": framework, "denied": true})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"op_id": opID, "framework": framework, "method": r.Method, "path_params": params})
}

func notFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 404, map[string]any{"op_id": "NOT_FOUND", "framework": framework})
}

func h(opID, template string, names ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { respond(w, r, opID, template, names...) }
}

func router() http.Handler {
	r := chi.NewRouter()
	r.NotFound(notFound)
	r.MethodNotAllowed(notFound) // CONTRACT: method mismatch is NOT_FOUND/404
	r.Get("/api/v1/accounts", h("listAccounts", "/api/v1/accounts"))
	r.Get("/api/v1/accounts/{id}", h("getAccount", "/api/v1/accounts/{id}", "id"))
	r.Put("/api/v1/accounts/{id}", h("updateAccount", "/api/v1/accounts/{id}", "id"))
	r.Delete("/api/v1/accounts/{id}", h("deleteAccount", "/api/v1/accounts/{id}", "id"))
	r.Post("/api/v1/accounts/{id}/actions", func(w http.ResponseWriter, r *http.Request) {
		op := r.URL.Query().Get("op") // url.Values.Get: duplicate keys -> FIRST value
		sub := "unknown"
		if op == "freeze" || op == "close" {
			sub = op
		}
		respond(w, r, "accountAction."+sub, "/api/v1/accounts/{id}/actions", "id")
	})
	r.Post("/api/v1/transfers", h("createTransfer", "/api/v1/transfers"))
	r.Post("/api/v1/graphql", func(w http.ResponseWriter, r *http.Request) {
		sub := "unknown"
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			if n, ok := m["operationName"].(string); ok && (n == "getProfile" || n == "deleteProfile") {
				sub = n
			}
		}
		respond(w, r, "graphql."+sub, "/api/v1/graphql")
	})
	r.Get("/api/v1/me", h("me", "/api/v1/me"))
	r.Get("/api/v1/admin/users", h("adminListUsers", "/api/v1/admin/users"))
	r.Delete("/api/v1/admin/users/{id}", h("adminDeleteUser", "/api/v1/admin/users/{id}", "id"))
	r.Get("/api/v1/health", h("health", "/api/v1/health"))
	r.Get("/api/v1/public/{file}", h("publicFile", "/api/v1/public/{file}", "file"))

	if routesV2 {
		// POST sharing the /accounts/{id} path with GET/PUT/DELETE.
		r.Post("/api/v1/accounts/{id}", h("postAccount", "/api/v1/accounts/{id}", "id"))
		// Nested same-method route.
		r.Get("/api/v1/accounts/{id}/statements", h("getStatements", "/api/v1/accounts/{id}/statements", "id"))
		r.Delete("/api/v1/accounts/{id}/statements/{sid}", h("deleteStatement", "/api/v1/accounts/{id}/statements/{sid}", "id", "sid"))
		// Catch-all: chi's wildcard binds the remainder (incl. '/') into URLParam "*"; logged as "path".
		r.Get("/api/v1/files/*", func(w http.ResponseWriter, r *http.Request) {
			rest := chi.URLParam(r, "*")
			dec := rest
			if r.URL.RawPath != "" {
				if d, err := url.PathUnescape(rest); err == nil {
					dec = d
				}
			}
			t := "/api/v1/files/{path}"
			canon := strings.Replace(t, "{path}", quote(dec), 1)
			finish(w, r, "catchAllFile", &t, map[string]string{"path": rest}, canon)
		})
	}

	// Prefix mount: a chi sub-router mounted at /api/v2.
	v2 := chi.NewRouter()
	v2.NotFound(notFound)
	v2.MethodNotAllowed(notFound)
	v2.Get("/accounts/{id}", h("getAccountV2", "/api/v2/accounts/{id}", "id"))
	r.Mount("/api/v2", v2)
	return r
}

func main() {
	if verifyMode != "off" && verifyMode != "origin-raw" && verifyMode != "origin-routed" {
		log.Fatalf("bad VERIFY_MODE=%s", verifyMode)
	}
	var handler http.Handler = router()
	if override {
		handler = handlers.HTTPMethodOverrideHandler(handler)
	}
	handler = logMW(handler)
	addr := ":" + envOr("PORT", "8080")
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
