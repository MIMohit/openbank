// Defence D-B, executor side: view-binding MAC check (CONTRACT sections 8 and 10).
// The verifier emits  X-Verified-View: v1;b64url(HMAC-SHA256(K, jti\nUPPER(method)\ncanon_path\njkt)).
// The executor recomputes it over its own view (effective method after HttpMethodOverrideMiddleware,
// matched route pattern with route values substituted, RFC 3986-normalised path); 401 on mismatch.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Bench.Defence;

public sealed record ViewMacResult(bool Ok, string Reason, string? Path);

public sealed class ViewMac
{
    public const string Header = "X-Verified-View";
    static readonly Regex Pct = new("%([0-9A-Fa-f]{2})", RegexOptions.CultureInvariant);
    static readonly Regex Abs = new(@"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*([^?#]*)", RegexOptions.CultureInvariant);
    static readonly Regex Value = new("^v1;[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant);
    static readonly Regex Plain = new(@"^[\x20-\x21\x23-\x5b\x5d-\x7e]*$", RegexOptions.CultureInvariant);
    const string SegmentSafe = "-._~!$&'()*+,;=:@";

    readonly byte[] _key;

    public ViewMac(byte[] key)
    {
        if (key is null || key.Length == 0) throw new ArgumentException("DEFENCE=db requires a non-empty VIEW_MAC_KEY");
        _key = (byte[])key.Clone();
    }

    static bool Unreserved(int c) => c < 0x80 && (char.IsAsciiLetterOrDigit((char)c) || c == '-' || c == '.' || c == '_' || c == '~');

    public static string RemoveDotSegments(string path) // RFC 3986 section 5.2.4
    {
        var inp = path;
        var output = new List<string>();
        while (inp.Length > 0)
        {
            if (inp.StartsWith("../", StringComparison.Ordinal)) inp = inp[3..];
            else if (inp.StartsWith("./", StringComparison.Ordinal)) inp = inp[2..];
            else if (inp.StartsWith("/./", StringComparison.Ordinal)) inp = "/" + inp[3..];
            else if (inp == "/.") inp = "/";
            else if (inp.StartsWith("/../", StringComparison.Ordinal)) { inp = "/" + inp[4..]; if (output.Count > 0) output.RemoveAt(output.Count - 1); }
            else if (inp == "/..") { inp = "/"; if (output.Count > 0) output.RemoveAt(output.Count - 1); }
            else if (inp == "." || inp == "..") inp = "";
            else
            {
                var i = inp.IndexOf('/', 1);
                output.Add(i == -1 ? inp : inp[..i]);
                inp = i == -1 ? "" : inp[i..];
            }
        }
        return string.Concat(output);
    }

    public static string NormalisePct(string s) => Pct.Replace(s, m =>
    {
        var c = Convert.ToInt32(m.Groups[1].Value, 16);
        return Unreserved(c) ? ((char)c).ToString() : "%" + m.Groups[1].Value.ToUpperInvariant();
    });

    public static string CanonPath(string uri)
    {
        string path;
        var a = Abs.Match(uri);
        if (!uri.StartsWith('/') && a.Success) path = a.Groups[1].Value;
        else { var i = uri.IndexOfAny(new[] { '?', '#' }); path = i < 0 ? uri : uri[..i]; }
        var p = RemoveDotSegments(NormalisePct(path));
        return p.Length == 0 ? "/" : p;
    }

    /// Same encoder as the executors' D-A: unreserved + sub-delims + ':' '@' literal.
    public static string EncSegment(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if (Unreserved(b) || (b < 0x80 && SegmentSafe.IndexOf((char)b) >= 0)) sb.Append((char)b);
            else sb.Append('%').Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    public static string Substitute(string template, IReadOnlyDictionary<string, string> p)
    {
        var outp = template;
        foreach (var kv in p) outp = outp.Replace("{" + kv.Key + "}", EncSegment(kv.Value));
        return outp;
    }

    // --------------------------------------------------- D-A/D-B path map (W23)
    static readonly Regex Pct25 = new("%25([0-9A-Fa-f]{2})", RegexOptions.CultureInvariant);

    /// DEFENCE_PATH_MAP file -> list of (public, internal) prefix pairs, longest internal first.
    public static List<(string Public, string Internal)> LoadRules(string? envValue)
    {
        var outp = new List<(string, string)>();
        if (string.IsNullOrEmpty(envValue)) return outp;
        try
        {
            var doc = JsonNode.Parse(File.ReadAllText(envValue));
            var rules = doc as JsonArray ?? doc?["rules"] as JsonArray;
            if (rules is null) return outp;
            foreach (var r in rules)
                outp.Add((((string?)r?["public"] ?? "").TrimEnd('/'), ((string?)r?["internal"] ?? "").TrimEnd('/')));
        }
        catch { return new List<(string, string)>(); }
        outp.Sort((x, y) => y.Item2.Length - x.Item2.Length);
        return outp;
    }

    public static string ToPublic(string path, List<(string Public, string Internal)> rules)
    {
        foreach (var (pub, intr) in rules)
            if (intr.Length > 0 && (path == intr || path.StartsWith(intr + "/", StringComparison.Ordinal))) return pub + path[intr.Length..];
        return path;
    }

    /// Wildcard values keep '/' literal (per-segment encode); %25XX collapses back to %XX.
    public static string EncValue(string v, bool wildcard)
    {
        var enc = wildcard ? string.Join("/", v.Split('/').Select(EncSegment)) : EncSegment(v);
        return Pct25.Replace(enc, "%$1");
    }

    public static string SubstitutePm(string template, IReadOnlyDictionary<string, string> p, ISet<string> wildcards)
    {
        var outp = template;
        foreach (var kv in p) outp = outp.Replace("{" + kv.Key + "}", EncValue(kv.Value, wildcards.Contains(kv.Key)));
        return outp;
    }

    static bool HasDotSegment(IReadOnlyDictionary<string, string> p, ISet<string> wildcards)
    {
        foreach (var kv in p)
        {
            var segs = wildcards.Contains(kv.Key) ? kv.Value.Split('/') : new[] { kv.Value };
            if (segs.Any(s => s == "." || s == "..")) return true;
        }
        return false;
    }

    static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[] B64uDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    public static string? Thumbprint(JsonNode? jwk)
    {
        if (jwk is not JsonObject o || o["kty"] is not JsonValue ktyv || !ktyv.TryGetValue<string>(out var kty)) return null;
        string[]? members = kty switch
        {
            "EC" => new[] { "crv", "kty", "x", "y" },
            "RSA" => new[] { "e", "kty", "n" },
            "OKP" => new[] { "crv", "kty", "x" },
            _ => null,
        };
        if (members is null) return null;
        var sb = new StringBuilder("{");
        for (var i = 0; i < members.Length; i++)
        {
            if (o[members[i]] is not JsonValue v || !v.TryGetValue<string>(out var s) || !Plain.IsMatch(s)) return null;
            sb.Append(i == 0 ? "" : ",").Append('"').Append(members[i]).Append("\":\"").Append(s).Append('"');
        }
        sb.Append('}');
        return B64u(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }

    /// (jti, jkt) from the DPoP proof, parsed WITHOUT signature verification; null if unusable.
    public static (string Jti, string Jkt)? DpopBinding(string dpop)
    {
        try
        {
            var parts = dpop.Trim().Split('.');
            if (parts.Length != 3) return null;
            var hdr = JsonNode.Parse(B64uDecode(parts[0]));
            var claims = JsonNode.Parse(B64uDecode(parts[1]));
            var jkt = Thumbprint(hdr?["jwk"]);
            if (claims?["jti"] is JsonValue j && j.TryGetValue<string>(out var jti) && jkt is not null) return (jti, jkt);
            return null;
        }
        catch { return null; }
    }

    public static string Mac(byte[] key, string jti, string method, string path, string jkt)
    {
        var msg = string.Join("\n", jti, method.ToUpperInvariant(), CanonPath(path), jkt);
        return "v1;" + B64u(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(msg)));
    }

    /// viewValues/dpopValues: every received value of X-Verified-View / DPoP, in order.
    public ViewMacResult Check(IReadOnlyList<string> viewValues, IReadOnlyList<string> dpopValues, string method,
                               string template, IReadOnlyDictionary<string, string> p)
        => Check(viewValues, dpopValues, method, template, p, null, new HashSet<string>());

    /// pathmap=null: unchanged. pathmap=&lt;rules&gt; (W23): map to public space, wildcard-aware, per-segment dot guard.
    public ViewMacResult Check(IReadOnlyList<string> viewValues, IReadOnlyList<string> dpopValues, string method,
                               string template, IReadOnlyDictionary<string, string> p,
                               List<(string Public, string Internal)>? pathmap, ISet<string> wildcards)
    {
        if (viewValues.Count == 0) return new(false, "view_mac_missing", null);
        if (viewValues.Count > 1) return new(false, "view_mac_multiple", null);
        var got = viewValues[0].Trim(' ', '\t');
        if (!Value.IsMatch(got)) return new(false, "view_mac_malformed", null);
        if (dpopValues.Count != 1) return new(false, "view_mac_no_dpop", null);
        var b = DpopBinding(dpopValues[0]);
        if (b is null) return new(false, "view_mac_no_dpop", null);
        string path;
        if (pathmap is null)
        {
            if (p.Values.Any(v => v == "." || v == "..")) return new(false, "view_param_dot_segment", null);
            path = CanonPath(Substitute(template, p));
        }
        else
        {
            if (HasDotSegment(p, wildcards)) return new(false, "view_param_dot_segment", null);
            path = CanonPath(ToPublic(SubstitutePm(template, p, wildcards), pathmap));
        }
        var want = Mac(_key, b.Value.Jti, method, path, b.Value.Jkt);
        var ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(want), Encoding.UTF8.GetBytes(got));
        return new(ok, ok ? "ok" : "view_mac_mismatch", path);
    }
}
