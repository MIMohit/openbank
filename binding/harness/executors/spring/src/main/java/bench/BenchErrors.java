package bench;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.LinkedHashMap;
import java.util.Map;

/** Contract §3: any unmatched request (no route, or no route for this method) is 404 NOT_FOUND. */
@RestControllerAdvice
public class BenchErrors {
    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class,
            HttpRequestMethodNotSupportedException.class, HttpMediaTypeNotSupportedException.class})
    public ResponseEntity<Map<String, Object>> notFound(HttpServletRequest req) {
        req.removeAttribute(Bench.A_OP);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("op_id", "NOT_FOUND");
        m.put("framework", Bench.FRAMEWORK);
        m.put("method", req.getMethod());
        m.put("path_params", Map.of());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(m);
    }
}
