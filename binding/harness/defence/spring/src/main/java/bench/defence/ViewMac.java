package bench.defence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Defence D-B, executor side: view-binding MAC check (CONTRACT sections 8 and 10).
 * The verifier emits {@code X-Verified-View: v1;b64url(HMAC-SHA256(K, jti\nUPPER(method)\ncanon_path\njkt))}.
 * The executor recomputes it over its own view (effective method after HiddenHttpMethodFilter, matched
 * pattern with the URI template variables substituted, RFC 3986-normalised path) and rejects on mismatch.
 */
public final class ViewMac {
    public static final String HEADER = "X-Verified-View";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern PCT = Pattern.compile("%([0-9A-Fa-f]{2})");
    private static final Pattern ABS = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*([^?#]*).*$", Pattern.DOTALL);
    private static final Pattern VALUE = Pattern.compile("^v1;[A-Za-z0-9_-]{43}$");
    private static final Pattern PLAIN = Pattern.compile("^[\\x20-\\x21\\x23-\\x5b\\x5d-\\x7e]*$");
    private static final String SEGMENT_SAFE = "-._~!$&'()*+,;=:@";

    public record Result(boolean ok, String reason, String path) {}

    private final byte[] key;

    public ViewMac(byte[] key) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("DEFENCE=db requires a non-empty VIEW_MAC_KEY");
        this.key = key.clone();
    }

    // ------------------------------------------------------------------ canonicalisation
    static boolean unreserved(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
    }

    public static String removeDotSegments(String path) {   // RFC 3986 section 5.2.4
        String in = path;
        List<String> out = new ArrayList<>();
        while (!in.isEmpty()) {
            if (in.startsWith("../")) in = in.substring(3);
            else if (in.startsWith("./")) in = in.substring(2);
            else if (in.startsWith("/./")) in = "/" + in.substring(3);
            else if (in.equals("/.")) in = "/";
            else if (in.startsWith("/../")) { in = "/" + in.substring(4); if (!out.isEmpty()) out.remove(out.size() - 1); }
            else if (in.equals("/..")) { in = "/"; if (!out.isEmpty()) out.remove(out.size() - 1); }
            else if (in.equals(".") || in.equals("..")) in = "";
            else {
                int i = in.indexOf('/', 1);
                out.add(i == -1 ? in : in.substring(0, i));
                in = i == -1 ? "" : in.substring(i);
            }
        }
        return String.join("", out);
    }

    public static String normalisePct(String s) {
        Matcher m = PCT.matcher(s);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            int c = Integer.parseInt(m.group(1), 16);
            m.appendReplacement(sb, Matcher.quoteReplacement(unreserved(c) ? String.valueOf((char) c) : "%" + m.group(1).toUpperCase()));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    public static String canonPath(String uri) {
        String path;
        Matcher a = ABS.matcher(uri);
        if (!uri.startsWith("/") && a.matches()) path = a.group(1);
        else {
            int i = indexOfAny(uri);
            path = i < 0 ? uri : uri.substring(0, i);
        }
        String p = removeDotSegments(normalisePct(path));
        return p.isEmpty() ? "/" : p;
    }

    private static int indexOfAny(String s) {
        int q = s.indexOf('?'), h = s.indexOf('#');
        return q < 0 ? h : (h < 0 ? q : Math.min(q, h));
    }

    /** Same encoder as the executors' D-A: unreserved + sub-delims + ':' '@' literal. */
    public static String encSegment(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c < 0x80 && unreserved(c)) || SEGMENT_SAFE.indexOf(c) >= 0) sb.append((char) c);
            else sb.append('%').append(String.format("%02X", c));
        }
        return sb.toString();
    }

    /** {name:regex} and {*name} are reduced to {name} first. */
    public static String normaliseTemplate(String t) {
        return t.replaceAll("\\{\\*?([A-Za-z0-9_]+)(?::[^}]*)?\\}", "{$1}");
    }

    public static String substitute(String template, Map<String, String> params) {
        String out = normaliseTemplate(template);
        for (Map.Entry<String, String> e : params.entrySet()) out = out.replace("{" + e.getKey() + "}", encSegment(e.getValue()));
        return out;
    }

    // ------------------------------------------------------------------ JOSE bits
    static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    public static String thumbprint(JsonNode jwk) {
        if (jwk == null || !jwk.isObject() || !jwk.path("kty").isTextual()) return null;
        String[] members = switch (jwk.get("kty").asText()) {
            case "EC" -> new String[]{"crv", "kty", "x", "y"};
            case "RSA" -> new String[]{"e", "kty", "n"};
            case "OKP" -> new String[]{"crv", "kty", "x"};
            default -> null;
        };
        if (members == null) return null;
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < members.length; i++) {
            JsonNode v = jwk.get(members[i]);
            if (v == null || !v.isTextual() || !PLAIN.matcher(v.asText()).matches()) return null;
            sb.append(i == 0 ? "" : ",").append('"').append(members[i]).append("\":\"").append(v.asText()).append('"');
        }
        sb.append('}');
        try {
            return b64u(MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    /** [jti, jkt] from the DPoP proof, parsed without signature verification; null if unusable. */
    public static String[] dpopBinding(String dpop) {
        try {
            String[] parts = dpop.trim().split("\\.", -1);
            if (parts.length != 3) return null;
            JsonNode hdr = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
            JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode jti = claims == null ? null : claims.get("jti");
            String jkt = hdr == null ? null : thumbprint(hdr.get("jwk"));
            if (jti == null || !jti.isTextual() || jkt == null) return null;
            return new String[]{jti.asText(), jkt};
        } catch (Exception e) {
            return null;
        }
    }

    public static String mac(byte[] key, String jti, String method, String path, String jkt) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            String msg = String.join("\n", jti, method.toUpperCase(java.util.Locale.ROOT), canonPath(path), jkt);
            return "v1;" + b64u(m.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ the check
    /** viewValues/dpopValues: every received value of X-Verified-View / DPoP, in order. */
    public Result check(List<String> viewValues, List<String> dpopValues, String method, String template, Map<String, String> params) {
        if (viewValues.isEmpty()) return new Result(false, "view_mac_missing", null);
        if (viewValues.size() > 1) return new Result(false, "view_mac_multiple", null);
        String got = viewValues.get(0).replaceAll("^[ \\t]+|[ \\t]+$", "");
        if (!VALUE.matcher(got).matches()) return new Result(false, "view_mac_malformed", null);
        if (dpopValues.size() != 1) return new Result(false, "view_mac_no_dpop", null);
        String[] b = dpopBinding(dpopValues.get(0));
        if (b == null) return new Result(false, "view_mac_no_dpop", null);
        for (String v : params.values()) if (".".equals(v) || "..".equals(v)) return new Result(false, "view_param_dot_segment", null);
        String path = canonPath(substitute(template, params));
        String want = mac(key, b[0], method, path, b[1]);
        boolean ok = MessageDigest.isEqual(want.getBytes(StandardCharsets.UTF_8), got.getBytes(StandardCharsets.UTF_8));
        return new Result(ok, ok ? "ok" : "view_mac_mismatch", path);
    }
}
