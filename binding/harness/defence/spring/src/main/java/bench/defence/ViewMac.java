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

    // ------------------------------------------------------------- D-A/D-B path map (W23)
    private static final Pattern PCT25 = Pattern.compile("%25([0-9A-Fa-f]{2})");

    /** DEFENCE_PATH_MAP file -> list of {public, internal} prefix pairs, longest internal first. */
    public static List<String[]> loadRules(String envValue) {
        List<String[]> out = new ArrayList<>();
        if (envValue == null || envValue.isEmpty()) return out;
        try {
            JsonNode doc = JSON.readTree(new java.io.File(envValue));
            JsonNode rules = doc.isArray() ? doc : doc.path("rules");
            for (JsonNode r : rules) {
                out.add(new String[]{r.path("public").asText().replaceAll("/+$", ""),
                        r.path("internal").asText().replaceAll("/+$", "")});
            }
        } catch (Exception e) { return new ArrayList<>(); }
        out.sort((x, y) -> y[1].length() - x[1].length());
        return out;
    }

    public static String toPublic(String path, List<String[]> rules) {
        for (String[] r : rules) {
            String pub = r[0], intr = r[1];
            if (!intr.isEmpty() && (path.equals(intr) || path.startsWith(intr + "/"))) return pub + path.substring(intr.length());
        }
        return path;
    }

    /** Wildcard values keep '/' literal (per-segment encode); %25XX collapses back to %XX. */
    public static String encValue(String v, boolean wildcard) {
        String enc;
        if (wildcard) {
            StringBuilder sb = new StringBuilder();
            String[] segs = v.split("/", -1);
            for (int i = 0; i < segs.length; i++) sb.append(i == 0 ? "" : "/").append(encSegment(segs[i]));
            enc = sb.toString();
        } else {
            enc = encSegment(v);
        }
        return PCT25.matcher(enc).replaceAll("%$1");
    }

    public static String substitutePm(String template, Map<String, String> params, java.util.Set<String> wildcards) {
        String out = normaliseTemplate(template);
        for (Map.Entry<String, String> e : params.entrySet()) out = out.replace("{" + e.getKey() + "}", encValue(e.getValue(), wildcards.contains(e.getKey())));
        return out;
    }

    static boolean hasDotSegment(Map<String, String> params, java.util.Set<String> wildcards) {
        for (Map.Entry<String, String> e : params.entrySet()) {
            String[] segs = wildcards.contains(e.getKey()) ? e.getValue().split("/", -1) : new String[]{e.getValue()};
            for (String s : segs) if (".".equals(s) || "..".equals(s)) return true;
        }
        return false;
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
        return check(viewValues, dpopValues, method, template, params, null, java.util.Collections.emptySet());
    }

    /** pathmap=null: unchanged. pathmap=<rules> (W23): map to public space, wildcard-aware, per-segment dot guard. */
    public Result check(List<String> viewValues, List<String> dpopValues, String method, String template,
                        Map<String, String> params, List<String[]> pathmap, java.util.Set<String> wildcards) {
        if (viewValues.isEmpty()) return new Result(false, "view_mac_missing", null);
        if (viewValues.size() > 1) return new Result(false, "view_mac_multiple", null);
        String got = viewValues.get(0).replaceAll("^[ \\t]+|[ \\t]+$", "");
        if (!VALUE.matcher(got).matches()) return new Result(false, "view_mac_malformed", null);
        if (dpopValues.size() != 1) return new Result(false, "view_mac_no_dpop", null);
        String[] b = dpopBinding(dpopValues.get(0));
        if (b == null) return new Result(false, "view_mac_no_dpop", null);
        String path;
        if (pathmap == null) {
            for (String v : params.values()) if (".".equals(v) || "..".equals(v)) return new Result(false, "view_param_dot_segment", null);
            path = canonPath(substitute(template, params));
        } else {
            if (hasDotSegment(params, wildcards)) return new Result(false, "view_param_dot_segment", null);
            path = canonPath(toPublic(substitutePm(template, params, wildcards), pathmap));
        }
        String want = mac(key, b[0], method, path, b[1]);
        boolean ok = MessageDigest.isEqual(want.getBytes(StandardCharsets.UTF_8), got.getBytes(StandardCharsets.UTF_8));
        return new Result(ok, ok ? "ok" : "view_mac_mismatch", path);
    }
}
