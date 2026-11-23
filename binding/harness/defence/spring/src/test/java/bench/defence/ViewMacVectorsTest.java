package bench.defence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ViewMacVectorsTest {
    static final JsonNode VEC;
    static {
        try {
            String p = System.getProperty("vectors", "../vectors.json");
            VEC = new ObjectMapper().readTree(new File(p));
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static List<String> list(JsonNode a) { List<String> l = new ArrayList<>(); a.forEach(n -> l.add(n.asText())); return l; }
    static Map<String, String> map(JsonNode o) { Map<String, String> m = new LinkedHashMap<>(); o.fields().forEachRemaining(e -> m.put(e.getKey(), e.getValue().asText())); return m; }
    static Stream<JsonNode> s(String k) { List<JsonNode> l = new ArrayList<>(); VEC.get(k).forEach(l::add); return l.stream(); }

    @TestFactory Stream<DynamicTest> canonPath() {
        return s("canon_path").map(v -> DynamicTest.dynamicTest("[" + v.get("in").asText() + "]", () -> assertEquals(v.get("out").asText(), ViewMac.canonPath(v.get("in").asText()))));
    }
    @TestFactory Stream<DynamicTest> thumbprint() {
        return s("thumbprint").map(v -> DynamicTest.dynamicTest(v.get("jwk").get("kty").asText(), () -> assertEquals(v.get("jkt").asText(), ViewMac.thumbprint(v.get("jwk")))));
    }
    @TestFactory Stream<DynamicTest> mac() {
        return s("mac").map(v -> DynamicTest.dynamicTest(v.get("uri").asText(), () -> assertEquals(v.get("out").asText(),
                ViewMac.mac(v.get("key").asText().getBytes(StandardCharsets.UTF_8), v.get("jti").asText(), v.get("method").asText(), v.get("uri").asText(), v.get("jkt").asText()))));
    }
    @TestFactory Stream<DynamicTest> substitute() {
        return s("substitute").map(v -> DynamicTest.dynamicTest(v.get("params").toString(), () -> assertEquals(v.get("out").asText(), ViewMac.substitute(v.get("template").asText(), map(v.get("params"))))));
    }
    @TestFactory Stream<DynamicTest> check() {
        return s("check").map(v -> DynamicTest.dynamicTest(v.get("name").asText(), () -> {
            ViewMac vm = new ViewMac(v.get("key").asText().getBytes(StandardCharsets.UTF_8));
            ViewMac.Result r = vm.check(list(v.get("headers").get("x-verified-view")), list(v.get("headers").get("dpop")),
                    v.get("method").asText(), v.get("template").asText(), map(v.get("params")));
            JsonNode e = v.get("expect");
            assertEquals(e.get("ok").asBoolean(), r.ok(), v.get("name").asText());
            assertEquals(e.get("reason").asText(), r.reason());
            if (!e.get("path").isNull()) assertEquals(e.get("path").asText(), r.path());
        }));
    }
    @Test void emptyKeyRefused() {
        assertThrows(IllegalArgumentException.class, () -> new ViewMac(new byte[0]));
    }
    @Test void templateConstraintsStripped() {
        assertEquals("/a/{id}/{rest}", ViewMac.normaliseTemplate("/a/{id:\\d+}/{*rest}"));
    }
}
