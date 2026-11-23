package bench;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Richer v1 route space (W15 ext-routes), registered only when ROUTES=v2 (App sets the
 * {@code bench.routes} property from the ROUTES env var). When off this bean is not created,
 * so the routes do not exist and :latest behaviour is unchanged.
 */
@RestController
@RequestMapping("/api/v1")
@ConditionalOnProperty(name = "bench.routes", havingValue = "v2")
public class RoutesV2Controller {

    /** POST sharing the /accounts/{id} path with GET/PUT/DELETE (HiddenHttpMethodFilter is POST-only). */
    @PostMapping("/accounts/{id}")
    public Object postAccount(HttpServletRequest r, @PathVariable String id) {
        return V1Controller.op(r, "postAccount", "/api/v1/accounts/{id}", V1Controller.p("id", id));
    }

    @GetMapping("/accounts/{id}/statements")
    public Object getStatements(HttpServletRequest r, @PathVariable String id) {
        return V1Controller.op(r, "getStatements", "/api/v1/accounts/{id}/statements", V1Controller.p("id", id));
    }

    @DeleteMapping("/accounts/{id}/statements/{sid}")
    public Object deleteStatement(HttpServletRequest r, @PathVariable String id, @PathVariable String sid) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("sid", sid);
        return V1Controller.op(r, "deleteStatement", "/api/v1/accounts/{id}/statements/{sid}", m);
    }

    /** Catch-all: Spring PathPattern {*path} captures the remainder (incl. '/') with a leading slash. */
    @GetMapping("/files/{*path}")
    public Object catchAllFile(HttpServletRequest r, @PathVariable String path) {
        return V1Controller.op(r, "catchAllFile", "/api/v1/files/{path}", V1Controller.p("path", path));
    }
}
