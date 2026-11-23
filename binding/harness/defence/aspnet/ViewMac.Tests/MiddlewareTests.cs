using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Bench.Defence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

/// Pipeline wired like harness/executors/aspnet: UseHttpMethodOverride (form field + header) -> UseRouting -> UseViewMac.
public class MiddlewareTests : IAsyncLifetime
{
    static readonly byte[] Key = Encoding.UTF8.GetBytes("adapter-key");
    static readonly string Dpop = VectorTests.Vec["check"]![0]!["headers"]!["dpop"]![0]!.GetValue<string>();
    static readonly (string Jti, string Jkt) B = ViewMac.DpopBinding(Dpop)!.Value;
    static string Mac(string m, string u) => ViewMac.Mac(Key, B.Jti, m, u, B.Jkt);

    WebApplication _app = null!;
    HttpClient _c = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        _app = builder.Build();
        _app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = "_method" });
        _app.UseHttpMethodOverride();
        _app.UseRouting();
        _app.UseViewMac(Key);
        IResult H(HttpContext c) => Results.Json(new { m = c.Request.Method, path = ((ViewMacResult)c.Items[ViewMacMiddleware.ItemKey]!).Path });
        var v1 = _app.MapGroup("/api/v1");
        v1.MapGet("/accounts/{id}", (HttpContext c, string id) => H(c));
        v1.MapDelete("/accounts/{id}", (HttpContext c, string id) => H(c));
        v1.MapGet("/public/{file}", (HttpContext c, string file) => H(c));
        v1.MapGet("/typed/{n:int}", (HttpContext c, int n) => H(c));
        _app.MapGroup("/api/v2").MapGet("/accounts/{id}", (HttpContext c, string id) => H(c));
        await _app.StartAsync();
        _c = _app.GetTestClient();
    }

    public async Task DisposeAsync() => await _app.DisposeAsync();

    async Task<(HttpStatusCode, JsonNode?)> Send(HttpMethod m, string target, string? view, Dictionary<string, string>? extra = null, HttpContent? body = null, string[]? views = null)
    {
        var req = new HttpRequestMessage(m, target) { Content = body };
        foreach (var v in views ?? (view is null ? Array.Empty<string>() : new[] { view })) req.Headers.TryAddWithoutValidation("X-Verified-View", v);
        req.Headers.TryAddWithoutValidation("DPoP", Dpop);
        foreach (var kv in extra ?? new()) req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        var res = await _c.SendAsync(req);
        var text = await res.Content.ReadAsStringAsync();
        return (res.StatusCode, text.Length > 0 ? JsonNode.Parse(text) : null);
    }

    [Fact]
    public async Task AllowGroupTemplate()
    {
        var (s, b) = await Send(HttpMethod.Get, "/api/v1/accounts/acc-alice-1", Mac("GET", "/api/v1/accounts/acc-alice-1"));
        Assert.Equal(HttpStatusCode.OK, s);
        Assert.Equal("/api/v1/accounts/acc-alice-1", b!["path"]!.GetValue<string>());
    }

    [Fact]
    public async Task PrefixGroupV2()
    {
        Assert.Equal(HttpStatusCode.OK, (await Send(HttpMethod.Get, "/api/v2/accounts/acc-alice-1", Mac("GET", "/api/v2/accounts/acc-alice-1"))).Item1);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(HttpMethod.Get, "/api/v2/accounts/acc-alice-1", Mac("GET", "/api/v1/accounts/acc-alice-1"))).Item1);
    }

    [Fact]
    public async Task ConstraintStrippedFromTemplate()
    {
        var (s, b) = await Send(HttpMethod.Get, "/api/v1/typed/42", Mac("GET", "/api/v1/typed/42"));
        Assert.Equal(HttpStatusCode.OK, s);
        Assert.Equal("/api/v1/typed/42", b!["path"]!.GetValue<string>());
    }

    [Fact]
    public async Task DecodedParamReencoded()
    {
        var (s, b) = await Send(HttpMethod.Get, "/api/v1/public/a%20b", Mac("GET", "/api/v1/public/a%20b"));
        Assert.Equal(HttpStatusCode.OK, s);
        Assert.Equal("/api/v1/public/a%20b", b!["path"]!.GetValue<string>());
    }

    [Fact]
    public async Task EncodedSlashParamFailsClosed()
    {
        // ASP.NET leaves %2F encoded in route values, so the re-encoded view is a%252Fb: a false reject, not a bypass.
        var (s, b) = await Send(HttpMethod.Get, "/api/v1/public/a%2Fb", Mac("GET", "/api/v1/public/a%2Fb"));
        Assert.Equal(HttpStatusCode.Unauthorized, s);
        Assert.Equal("view_mac_mismatch", b!["reason"]!.GetValue<string>());
    }

    [Fact]
    public async Task MethodOverrideRejected()
    {
        var over = new Dictionary<string, string> { ["X-HTTP-Method-Override"] = "DELETE" };
        var (s, b) = await Send(HttpMethod.Post, "/api/v1/accounts/acc-alice-1", Mac("POST", "/api/v1/accounts/acc-alice-1"), over);
        Assert.Equal(HttpStatusCode.Unauthorized, s);
        Assert.Equal("view_mac_mismatch", b!["reason"]!.GetValue<string>());
        (s, b) = await Send(HttpMethod.Post, "/api/v1/accounts/acc-alice-1", Mac("DELETE", "/api/v1/accounts/acc-alice-1"), over);
        Assert.Equal(HttpStatusCode.OK, s);
        Assert.Equal("DELETE", b!["m"]!.GetValue<string>());
        // form-field override
        var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["_method"] = "DELETE" });
        (s, _) = await Send(HttpMethod.Post, "/api/v1/accounts/acc-alice-1", Mac("POST", "/api/v1/accounts/acc-alice-1"), body: form);
        Assert.Equal(HttpStatusCode.Unauthorized, s);
    }

    [Fact]
    public async Task MissingDuplicateUnmatched()
    {
        Assert.Equal("view_mac_missing", (await Send(HttpMethod.Get, "/api/v1/accounts/acc-alice-1", null)).Item2!["reason"]!.GetValue<string>());
        var g = Mac("GET", "/api/v1/accounts/acc-alice-1");
        var (s, b) = await Send(HttpMethod.Get, "/api/v1/accounts/acc-alice-1", null, views: new[] { g, g });
        Assert.Equal(HttpStatusCode.Unauthorized, s);
        Assert.Equal("view_mac_multiple", b!["reason"]!.GetValue<string>());
        Assert.Equal(HttpStatusCode.NotFound, (await Send(HttpMethod.Get, "/api/v1/nope", null)).Item1);
    }
}
