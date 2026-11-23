using System.Text;
using System.Text.Json.Nodes;
using Bench.Defence;
using Xunit;

public class VectorTests
{
    public static readonly JsonNode Vec = JsonNode.Parse(File.ReadAllText(
        Environment.GetEnvironmentVariable("VECTORS") ?? Path.Combine(AppContext.BaseDirectory, "../../../../../vectors.json")))!;

    public static IEnumerable<object[]> Rows(string k) => Vec[k]!.AsArray().Select((n, i) => new object[] { i });
    static Dictionary<string, string> Map(JsonNode o) => o.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>());
    static List<string> List(JsonNode a) => a.AsArray().Select(n => n!.GetValue<string>()).ToList();

    [Theory, MemberData(nameof(Rows), "canon_path")]
    public void CanonPath(int i) { var v = Vec["canon_path"]![i]!; Assert.Equal(v["out"]!.GetValue<string>(), ViewMac.CanonPath(v["in"]!.GetValue<string>())); }

    [Theory, MemberData(nameof(Rows), "thumbprint")]
    public void Thumbprint(int i) { var v = Vec["thumbprint"]![i]!; Assert.Equal(v["jkt"]!.GetValue<string>(), ViewMac.Thumbprint(v["jwk"])); }

    [Theory, MemberData(nameof(Rows), "mac")]
    public void Mac(int i)
    {
        var v = Vec["mac"]![i]!;
        Assert.Equal(v["out"]!.GetValue<string>(), ViewMac.Mac(Encoding.UTF8.GetBytes(v["key"]!.GetValue<string>()), v["jti"]!.GetValue<string>(),
            v["method"]!.GetValue<string>(), v["uri"]!.GetValue<string>(), v["jkt"]!.GetValue<string>()));
    }

    [Theory, MemberData(nameof(Rows), "substitute")]
    public void Substitute(int i) { var v = Vec["substitute"]![i]!; Assert.Equal(v["out"]!.GetValue<string>(), ViewMac.Substitute(v["template"]!.GetValue<string>(), Map(v["params"]!))); }

    [Theory, MemberData(nameof(Rows), "check")]
    public void Check(int i)
    {
        var v = Vec["check"]![i]!;
        var vm = new ViewMac(Encoding.UTF8.GetBytes(v["key"]!.GetValue<string>()));
        var r = vm.Check(List(v["headers"]!["x-verified-view"]!), List(v["headers"]!["dpop"]!), v["method"]!.GetValue<string>(),
                         v["template"]!.GetValue<string>(), Map(v["params"]!));
        var e = v["expect"]!;
        Assert.Equal((e["ok"]!.GetValue<bool>(), e["reason"]!.GetValue<string>()), (r.Ok, r.Reason));
        if (e["path"] is not null) Assert.Equal(e["path"]!.GetValue<string>(), r.Path);
    }

    [Fact]
    public void EmptyKeyRefused() => Assert.Throws<ArgumentException>(() => new ViewMac(Array.Empty<byte>()));
}
