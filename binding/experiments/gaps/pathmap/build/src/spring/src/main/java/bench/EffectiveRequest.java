package bench;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/** Reports the effective method recorded by the innermost filter (see EffectiveMethodFilter). */
class EffectiveRequest extends HttpServletRequestWrapper {
    EffectiveRequest(HttpServletRequest req) { super(req); }

    @Override
    public String getMethod() {
        Object m = getRequest().getAttribute("bench.effective_method");
        return m != null ? (String) m : super.getMethod();
    }
}
