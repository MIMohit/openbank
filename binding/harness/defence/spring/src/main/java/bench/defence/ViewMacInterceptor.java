package bench.defence;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

/**
 * Spring MVC adapter. preHandle() runs after handler mapping (so the best-matching pattern, which
 * already includes any PathMatchConfigurer prefix, and the decoded URI template variables are known)
 * and after servlet filters such as HiddenHttpMethodFilter (so getMethod() is the effective method).
 * Register with {@code registry.addInterceptor(new ViewMacInterceptor(key))} in a WebMvcConfigurer.
 */
public class ViewMacInterceptor implements HandlerInterceptor {
    public static final String ATTR = "bench.viewmac";
    private final ViewMac viewMac;

    public ViewMacInterceptor(byte[] key) { this.viewMac = new ViewMac(key); }

    @SuppressWarnings("unchecked")
    public static ViewMac.Result evaluate(ViewMac vm, HttpServletRequest req, String template, Map<String, String> vars) {
        return vm.check(Collections.list(req.getHeaders(ViewMac.HEADER)), Collections.list(req.getHeaders("DPoP")),
                req.getMethod(), template, vars == null ? Map.of() : vars);
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) throws Exception {
        // Only controller methods are bench operations; leave static-resource/error handlers alone
        if (!(handler instanceof org.springframework.web.method.HandlerMethod)) return true;
        String pattern = (String) req.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        Map<String, String> vars = (Map<String, String>) req.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        ViewMac.Result r = pattern == null ? new ViewMac.Result(false, "view_route_unknown", null) : evaluate(viewMac, req, pattern, vars);
        req.setAttribute(ATTR, r);
        if (r.ok()) return true;
        res.setStatus(401);
        res.setHeader("WWW-Authenticate", "DPoP error=\"invalid_token\"");
        res.setContentType("application/json");
        res.getOutputStream().write(("{\"error\":\"view_binding\",\"reason\":\"" + r.reason() + "\"}").getBytes(StandardCharsets.UTF_8));
        return false;
    }
}
