package bench.defence;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.HandlerTypePredicate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.File;
import java.lang.annotation.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Spring Boot slice wired like harness/executors/spring: addPathPrefix for /api/v2, HiddenHttpMethodFilter on. */
@SpringBootTest(classes = ViewMacInterceptorTest.TestApp.class, properties = "spring.mvc.hiddenmethod.filter.enabled=true")
@AutoConfigureMockMvc
class ViewMacInterceptorTest {
    static final byte[] KEY = "adapter-key".getBytes(StandardCharsets.UTF_8);
    static final String DPOP;
    static final String[] B;
    static {
        try {
            DPOP = new ObjectMapper().readTree(new File(System.getProperty("vectors", "../vectors.json")))
                    .get("check").get(0).get("headers").get("dpop").get(0).asText();
        } catch (Exception e) { throw new RuntimeException(e); }
        B = ViewMac.dpopBinding(DPOP);
    }
    static String mac(String m, String u) { return ViewMac.mac(KEY, B[0], m, u, B[1]); }

    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) @interface V2 {}

    @SpringBootApplication
    @org.springframework.context.annotation.Import({V1.class, V2Ctl.class}) // nested test classes are not component-scanned
    static class TestApp implements WebMvcConfigurer {
        @Override public void addInterceptors(InterceptorRegistry r) { r.addInterceptor(new ViewMacInterceptor(KEY)); }
        @Override public void configurePathMatch(PathMatchConfigurer c) { c.addPathPrefix("/api/v2", HandlerTypePredicate.forAnnotation(V2.class)); }
    }

    @RestController @RequestMapping("/api/v1")
    static class V1 {
        static Object body(HttpServletRequest r) { return Map.of("m", r.getMethod(), "path", ((ViewMac.Result) r.getAttribute(ViewMacInterceptor.ATTR)).path()); }
        @GetMapping("/accounts/{id}") Object get(HttpServletRequest r, @PathVariable String id) { return body(r); }
        @DeleteMapping("/accounts/{id}") Object del(HttpServletRequest r, @PathVariable String id) { return body(r); }
        @GetMapping("/public/{file}") Object pub(HttpServletRequest r, @PathVariable String file) { return body(r); }
    }

    @RestController @V2
    static class V2Ctl {
        @GetMapping("/accounts/{id}") Object get(HttpServletRequest r, @PathVariable String id) { return V1.body(r); }
    }

    @Autowired MockMvc mvc;

    @Test void allowAndTemplate() throws Exception {
        mvc.perform(get("/api/v1/accounts/acc-alice-1").header("X-Verified-View", mac("GET", "/api/v1/accounts/acc-alice-1")).header("DPoP", DPOP))
                .andExpect(status().isOk()).andExpect(jsonPath("$.path").value("/api/v1/accounts/acc-alice-1"));
    }

    @Test void prefixMount() throws Exception {
        mvc.perform(get("/api/v2/accounts/acc-alice-1").header("X-Verified-View", mac("GET", "/api/v2/accounts/acc-alice-1")).header("DPoP", DPOP))
                .andExpect(status().isOk()).andExpect(jsonPath("$.path").value("/api/v2/accounts/acc-alice-1"));
        mvc.perform(get("/api/v2/accounts/acc-alice-1").header("X-Verified-View", mac("GET", "/api/v1/accounts/acc-alice-1")).header("DPoP", DPOP))
                .andExpect(status().isUnauthorized());
    }

    @Test void decodedParamReencoded() throws Exception {
        mvc.perform(get("/api/v1/public/{f}", "a b").header("X-Verified-View", mac("GET", "/api/v1/public/a%20b")).header("DPoP", DPOP))
                .andExpect(status().isOk()).andExpect(jsonPath("$.path").value("/api/v1/public/a%20b"));
    }

    @Test void hiddenMethodOverrideRejected() throws Exception {
        // verifier saw POST; HiddenHttpMethodFilter turns _method=DELETE into DELETE
        mvc.perform(post("/api/v1/accounts/acc-alice-1").param("_method", "DELETE")
                        .header("X-Verified-View", mac("POST", "/api/v1/accounts/acc-alice-1")).header("DPoP", DPOP))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.reason").value("view_mac_mismatch"))
                .andExpect(header().string("WWW-Authenticate", "DPoP error=\"invalid_token\""));
        mvc.perform(post("/api/v1/accounts/acc-alice-1").param("_method", "DELETE")
                        .header("X-Verified-View", mac("DELETE", "/api/v1/accounts/acc-alice-1")).header("DPoP", DPOP))
                .andExpect(status().isOk()).andExpect(jsonPath("$.m").value("DELETE"));
    }

    @Test void unmatchedNotIntercepted() throws Exception {
        // only @RequestMapping handlers are checked; unmatched requests still get the framework's 404
        mvc.perform(get("/api/v1/nope")).andExpect(status().isNotFound());
    }

    @Test void missingAndDuplicate() throws Exception {
        mvc.perform(get("/api/v1/accounts/acc-alice-1").header("DPoP", DPOP))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.reason").value("view_mac_missing"));
        String g = mac("GET", "/api/v1/accounts/acc-alice-1");
        mvc.perform(get("/api/v1/accounts/acc-alice-1").header("X-Verified-View", g, g).header("DPoP", DPOP))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.reason").value("view_mac_multiple"));
    }
}
