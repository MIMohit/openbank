package bench;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;

import java.io.FileOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Shared bench-API helpers: identity, origin verification, JSONL logging. */
public final class Bench {
    private Bench() {}

    public static final ObjectMapper JSON = new ObjectMapper();
    public static final String FRAMEWORK = env("FRAMEWORK_TAG", "spring");
    public static final String VERIFY_MODE = env("VERIFY_MODE", "off");
    public static final String VERIFIER_URL = env("VERIFIER_URL", "http://verifier:9100/authz/orig");
    public static final String LOG_FILE = env("LOG_FILE", "/logs/executor.jsonl");
    /** Defence D-B (binding/harness/defence/spring): DEFENCE=off|db, key from VIEW_MAC_KEY. */
    public static final String DEFENCE = env("DEFENCE", "off".equals(VERIFY_MODE) ? "db" : "off");
    static final bench.defence.ViewMac VIEW_MAC = "db".equals(DEFENCE)
            ? new bench.defence.ViewMac(env("VIEW_MAC_KEY", "").getBytes(StandardCharsets.UTF_8)) : null;
    public static final String A_DEFENCE_REASON = "bench.defence_reason";
    public static final String DEFENCE_PATH_MAP = env("DEFENCE_PATH_MAP", "");
    public static final java.util.Set<String> DEFENCE_WILDCARDS = new java.util.HashSet<>(java.util.Arrays.asList(env("DEFENCE_WILDCARDS", "path").split(",")));
    static java.util.List<String[]> pathmapRules() { return DEFENCE_PATH_MAP.isEmpty() ? null : bench.defence.ViewMac.loadRules(DEFENCE_PATH_MAP); }

    // request attribute keys
    public static final String A_RAW_METHOD = "bench.raw_method";
    public static final String A_RAW_TARGET = "bench.raw_target";
    public static final String A_OP = "bench.op_id";
    public static final String A_TEMPLATE = "bench.route_template";
    public static final String A_PARAMS = "bench.path_params";
    public static final String A_DENIED = "bench.denied";

    private static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(3)).build();
    private static final List<String> TRUST_PREFIXES = List.of(
            "x-forwarded-", "x-original-", "x-verified-", "x-client-cert", "client-cert",
            "x-forwarded-client-cert", "x-auth-");

    static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isEmpty() ? d : v;
    }

    /** Interpretation #6: keep RFC 3986 unreserved + sub-delims + ':' '@' literal, percent-encode the rest. */
    static String encSegment(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || "-._~!$&'()*+,;=:@".indexOf(c) >= 0) {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    static String substitute(String template, Map<String, String> params) {
        String out = template;
        for (Map.Entry<String, String> e : params.entrySet()) {
            out = out.replace("{" + e.getKey() + "}", encSegment(e.getValue()));
        }
        return out;
    }

    /**
     * Called first in every handler. Records the matched operation and, if VERIFY_MODE is on,
     * calls the verifier before any handler logic. Returns true when the request may proceed.
     */
    public static boolean enter(HttpServletRequest req, String opId, String template, Map<String, String> params) {
        req.setAttribute(A_OP, opId);
        req.setAttribute(A_TEMPLATE, template);
        req.setAttribute(A_PARAMS, params);
        if (VIEW_MAC != null) {   // D-B: X-Verified-View must match the view this executor dispatched on
            bench.defence.ViewMac.Result r = VIEW_MAC.check(Collections.list(req.getHeaders("X-Verified-View")),
                    Collections.list(req.getHeaders("DPoP")), req.getMethod(), template, params, pathmapRules(), DEFENCE_WILDCARDS);
            if (!r.ok()) {
                req.setAttribute(A_DENIED, Boolean.TRUE);
                req.setAttribute(A_DEFENCE_REASON, r.reason());
                return false;
            }
        }
        if ("off".equals(VERIFY_MODE)) return true;
        String method, uri;
        if ("origin-routed".equals(VERIFY_MODE)) {
            method = req.getMethod();                 // effective (after HiddenHttpMethodFilter)
            java.util.List<String[]> _r = pathmapRules();
            uri = _r == null ? substitute(template, params) : bench.defence.ViewMac.toPublic(bench.defence.ViewMac.substitutePm(template, params, DEFENCE_WILDCARDS), _r);
        } else {                                      // origin-raw
            method = (String) req.getAttribute(A_RAW_METHOD);
            uri = (String) req.getAttribute(A_RAW_TARGET);
        }
        boolean allow;
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(VERIFIER_URL))
                    .timeout(Duration.ofSeconds(5)).GET()
                    .header("X-Original-Method", method)
                    .header("X-Original-URI", uri)
                    .header("X-Original-Host", req.getHeader("Host") == null ? "" : req.getHeader("Host"));
            if (req.getHeader("Authorization") != null) b.header("Authorization", req.getHeader("Authorization"));
            if (req.getHeader("DPoP") != null) b.header("DPoP", req.getHeader("DPoP"));
            HttpResponse<Void> r = HTTP.send(b.build(), HttpResponse.BodyHandlers.discarding());
            allow = r.statusCode() >= 200 && r.statusCode() < 300;
        } catch (Exception e) {
            allow = false;                            // fail closed
        }
        if (!allow) req.setAttribute(A_DENIED, Boolean.TRUE);
        return allow;
    }

    public static Map<String, Object> body(HttpServletRequest req, String opId, Map<String, String> params) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("op_id", opId);
        m.put("framework", FRAMEWORK);
        m.put("method", req.getMethod());
        m.put("path_params", params);
        return m;
    }

    public static Map<String, Object> deniedBody(String opId) {
        return deniedBody(opId, null);
    }

    public static Map<String, Object> deniedBody(String opId, Object reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("op_id", opId);
        m.put("framework", FRAMEWORK);
        m.put("denied", true);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    static String jti(String dpop) {
        if (dpop == null) return null;
        try {
            String[] parts = dpop.trim().split("\\.");
            if (parts.length < 2) return null;
            byte[] raw = Base64.getUrlDecoder().decode(parts[1].replace("=", ""));
            JsonNode n = JSON.readTree(raw);
            JsonNode j = n == null ? null : n.get("jti");
            return j != null && j.isTextual() ? j.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    static void log(HttpServletRequest req, int status, String rawMethod, String rawTarget, String rawQuery) {
        Map<String, Object> m = new LinkedHashMap<>();
        Object op = req.getAttribute(A_OP);
        Object params = req.getAttribute(A_PARAMS);
        m.put("ts", Instant.now().truncatedTo(ChronoUnit.MILLIS).toString());
        m.put("framework", FRAMEWORK);
        m.put("jti", jti(req.getHeader("DPoP")));
        m.put("op_id", op == null ? "NOT_FOUND" : op);
        m.put("route_template", req.getAttribute(A_TEMPLATE));
        m.put("raw_method", rawMethod);
        m.put("effective_method", req.getMethod());
        m.put("raw_target", rawTarget);
        m.put("path_params", params == null ? Map.of() : params);
        m.put("query", rawQuery == null ? "" : rawQuery);
        Map<String, String> trust = new LinkedHashMap<>();
        for (String name : Collections.list(req.getHeaderNames())) {
            String lower = name.toLowerCase();
            for (String p : TRUST_PREFIXES) {
                if (lower.startsWith(p)) {
                    trust.put(lower, String.join(", ", Collections.list(req.getHeaders(name))));
                    break;
                }
            }
        }
        m.put("trust_headers", trust);
        m.put("denied", req.getAttribute(A_DENIED) != null);
        m.put("status", status);
        try {
            String line = JSON.writeValueAsString(m);
            synchronized (Bench.class) {
                System.out.println(line);
                System.out.flush();
                try {
                    Path p = Path.of(LOG_FILE);
                    if (p.getParent() != null) Files.createDirectories(p.getParent());
                    try (FileOutputStream fos = new FileOutputStream(p.toFile(), true)) {
                        fos.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                } catch (Exception ignored) {
                    // /logs not mounted or not writable: stdout still has the line
                }
            }
        } catch (Exception ignored) {
        }
    }
}
