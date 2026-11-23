package bench;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Runs before every other filter (in particular before Spring Boot's
 * OrderedHiddenHttpMethodFilter, order -10000), so it sees the raw method.
 * After the chain it writes the JSONL log line.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CaptureFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String rawMethod = req.getMethod();
        String q = req.getQueryString();
        // Tomcat's getRequestURI() is the undecoded path of the request line (incl. ;params);
        // the query is re-attached verbatim.
        String rawTarget = req.getRequestURI() + (q == null ? "" : "?" + q);
        req.setAttribute(Bench.A_RAW_METHOD, rawMethod);
        req.setAttribute(Bench.A_RAW_TARGET, rawTarget);
        try {
            chain.doFilter(req, res);
        } finally {
            // req here is the original request; the effective method is visible on the
            // wrapper created by HiddenHttpMethodFilter, which handlers store as an attribute.
            Bench.log(new EffectiveRequest(req), res.getStatus(), rawMethod, rawTarget, q);
        }
    }
}
