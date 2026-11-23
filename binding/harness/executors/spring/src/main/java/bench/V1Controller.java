package bench;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class V1Controller {

    static ResponseEntity<Map<String, Object>> op(HttpServletRequest req, String opId, String template,
                                                   Map<String, String> params) {
        if (!Bench.enter(req, opId, template, params)) {
            return ResponseEntity.status(401).body(Bench.deniedBody(opId));
        }
        return ResponseEntity.ok(Bench.body(req, opId, params));
    }

    static Map<String, String> p(String k, String v) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put(k, v);
        return m;
    }

    @GetMapping("/accounts")
    public Object listAccounts(HttpServletRequest r) { return op(r, "listAccounts", "/api/v1/accounts", Map.of()); }

    @GetMapping("/accounts/{id}")
    public Object getAccount(HttpServletRequest r, @PathVariable String id) {
        return op(r, "getAccount", "/api/v1/accounts/{id}", p("id", id));
    }

    @PutMapping("/accounts/{id}")
    public Object updateAccount(HttpServletRequest r, @PathVariable String id) {
        return op(r, "updateAccount", "/api/v1/accounts/{id}", p("id", id));
    }

    @DeleteMapping("/accounts/{id}")
    public Object deleteAccount(HttpServletRequest r, @PathVariable String id) {
        return op(r, "deleteAccount", "/api/v1/accounts/{id}", p("id", id));
    }

    /** G1 query dispatch, using Spring's idiomatic @RequestParam binding. */
    @PostMapping("/accounts/{id}/actions")
    public Object accountAction(HttpServletRequest r, @PathVariable String id,
                                @RequestParam(name = "op", required = false) String op) {
        String opId = "freeze".equals(op) ? "accountAction.freeze"
                : "close".equals(op) ? "accountAction.close" : "accountAction.unknown";
        return op(r, opId, "/api/v1/accounts/{id}/actions", p("id", id));
    }

    @PostMapping("/transfers")
    public Object createTransfer(HttpServletRequest r) { return op(r, "createTransfer", "/api/v1/transfers", Map.of()); }

    /** G1 body dispatch: the raw body is parsed as JSON whatever the Content-Type. */
    @PostMapping("/graphql")
    public Object graphql(HttpServletRequest r, @RequestBody(required = false) byte[] body) {
        String name = null;
        try {
            if (body != null && body.length > 0) {
                JsonNode n = Bench.JSON.readTree(body);
                JsonNode o = n == null ? null : n.get("operationName");
                if (o != null && o.isTextual()) name = o.asText();
            }
        } catch (Exception ignored) {
        }
        String opId = "getProfile".equals(name) ? "graphql.getProfile"
                : "deleteProfile".equals(name) ? "graphql.deleteProfile" : "graphql.unknown";
        return op(r, opId, "/api/v1/graphql", Map.of());
    }

    @GetMapping("/me")
    public Object me(HttpServletRequest r) { return op(r, "me", "/api/v1/me", Map.of()); }

    @GetMapping("/admin/users")
    public Object adminListUsers(HttpServletRequest r) { return op(r, "adminListUsers", "/api/v1/admin/users", Map.of()); }

    @DeleteMapping("/admin/users/{id}")
    public Object adminDeleteUser(HttpServletRequest r, @PathVariable String id) {
        return op(r, "adminDeleteUser", "/api/v1/admin/users/{id}", p("id", id));
    }

    @GetMapping("/health")
    public Object health(HttpServletRequest r) { return op(r, "health", "/api/v1/health", Map.of()); }

    @GetMapping("/public/{file}")
    public Object publicFile(HttpServletRequest r, @PathVariable String file) {
        return op(r, "publicFile", "/api/v1/public/{file}", p("file", file));
    }
}
