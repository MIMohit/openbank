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

/** Runs last; records the method that the DispatcherServlet will route on. */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class EffectiveMethodFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        req.setAttribute("bench.effective_method", req.getMethod());
        chain.doFilter(req, res);
    }
}
