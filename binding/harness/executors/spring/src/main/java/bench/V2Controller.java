package bench;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** Mounted under /api/v2 by WebConfig's path prefix; the mapping itself is relative. */
@RestController
@V2Api
public class V2Controller {
    @GetMapping("/accounts/{id}")
    public Object getAccountV2(HttpServletRequest r, @PathVariable String id) {
        return V1Controller.op(r, "getAccountV2", "/api/v2/accounts/{id}", V1Controller.p("id", id));
    }
}
