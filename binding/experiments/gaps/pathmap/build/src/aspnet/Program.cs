// Bench API executor for ASP.NET Core (minimal APIs). Contract: binding/CONTRACT.md §3.
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

string Env(string k, string d) { var v = Environment.GetEnvironmentVariable(k); return string.IsNullOrEmpty(v) ? d : v; }
var framework = Env("FRAMEWORK_TAG", "aspnet");
var verifyMode = Env("VERIFY_MODE", "off");
var verifierUrl = Env("VERIFIER_URL", "http://verifier:9100/authz/orig");
var logFile = Env("LOG_FILE", "/logs/executor.jsonl");
var overrideOn = Env("OVERRIDE", "off") == "on";
// Defence D-B (binding/harness/defence/aspnet/ViewMac): DEFENCE=off|db, key from VIEW_MAC_KEY.
var defence = Env("DEFENCE", verifyMode == "off" ? "db" : "off");
if (defence != "off" && defence != "db") { Console.Error.WriteLine("bad DEFENCE"); Environment.Exit(2); }
var viewMac = defence == "db" ? new Bench.Defence.ViewMac(Encoding.UTF8.GetBytes(Env("VIEW_MAC_KEY", ""))) : null;
var defencePathMap = Env("DEFENCE_PATH_MAP", "");
var defenceWildcards = (ISet<string>)new HashSet<string>(Env("DEFENCE_WILDCARDS", "path").Split(',', StringSplitOptions.RemoveEmptyEntries));
Func<List<(string, string)>?> pathmapRules = () => defencePathMap.Length > 0 ? Bench.Defence.ViewMac.LoadRules(defencePathMap) : null;
// ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes). Off => :latest behaviour.
var routesV2 = Env("ROUTES", "off").ToLowerInvariant() == "v2";
var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
var jsonOpts = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
var logLock = new object();
string[] trustPrefixes = { "x-forwarded-", "x-original-", "x-verified-", "x-client-cert", "client-cert",
                           "x-forwarded-client-cert", "x-auth-" };

string? Jti(string? dpop)
{
    if (string.IsNullOrEmpty(dpop)) return null;
    try
    {
        var parts = dpop.Trim().Split('.');
        if (parts.Length < 2) return null;
        var s = parts[1].Replace('-', '+').Replace('_', '/').TrimEnd('=');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        var node = JsonNode.Parse(Convert.FromBase64String(s));
        var j = node?["jti"];
        return j is JsonValue v && v.TryGetValue<string>(out var str) ? str : null;
    }
    catch { return null; }
}

string EncSegment(string s)
{
    var sb = new StringBuilder();
    foreach (var b in Encoding.UTF8.GetBytes(s))
    {
        char c = (char)b;
        // interpretation #6: unreserved + sub-delims + ':' '@' stay literal (Python quote safe="-._~!$&'()*+,;=:@")
        if (char.IsAsciiLetterOrDigit(c) || "-._~!$&'()*+,;=:@".IndexOf(c) >= 0) sb.Append(c);
        else sb.Append('%').Append(b.ToString("X2"));
    }
    return sb.ToString();
}

// 1. Outermost: capture the raw request, write the log line, map unmatched to 404 NOT_FOUND.
app.Use(async (ctx, next) =>
{
    var rawMethod = ctx.Request.Method;
    // Kestrel exposes the request-target exactly as received on the request line.
    var rawTarget = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget ?? (ctx.Request.Path + ctx.Request.QueryString);
    ctx.Items["raw_method"] = rawMethod;
    ctx.Items["raw_target"] = rawTarget;
    await next(ctx);
    if (!ctx.Items.ContainsKey("op_id") && !ctx.Response.HasStarted
        && (ctx.Response.StatusCode == 404 || ctx.Response.StatusCode == 405))
    {
        ctx.Response.Clear();
        ctx.Response.StatusCode = 404;
        await ctx.Response.WriteAsJsonAsync(new Dictionary<string, object?>
        {
            ["op_id"] = "NOT_FOUND", ["framework"] = framework, ["method"] = ctx.Request.Method,
            ["path_params"] = new Dictionary<string, string>()
        }, jsonOpts);
    }
    var q = ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value!.Substring(1) : "";
    var qi = rawTarget.IndexOf('?');
    if (qi >= 0) q = rawTarget.Substring(qi + 1);
    var trust = new Dictionary<string, string>();
    foreach (var h in ctx.Request.Headers)
    {
        var lower = h.Key.ToLowerInvariant();
        if (trustPrefixes.Any(p => lower.StartsWith(p))) trust[lower] = string.Join(", ", h.Value.ToArray());
    }
    var rec = new Dictionary<string, object?>
    {
        ["ts"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
        ["framework"] = framework,
        ["jti"] = Jti(ctx.Request.Headers["DPoP"].FirstOrDefault()),
        ["op_id"] = ctx.Items.TryGetValue("op_id", out var op) ? op : "NOT_FOUND",
        ["route_template"] = ctx.Items.TryGetValue("route_template", out var rt) ? rt : null,
        ["raw_method"] = rawMethod,
        ["effective_method"] = ctx.Request.Method,
        ["raw_target"] = rawTarget,
        ["path_params"] = ctx.Items.TryGetValue("path_params", out var pp) ? pp : new Dictionary<string, string>(),
        ["query"] = q,
        ["trust_headers"] = trust,
        ["denied"] = ctx.Items.ContainsKey("denied"),
        ["status"] = ctx.Response.StatusCode,
    };
    var line = JsonSerializer.Serialize(rec, jsonOpts);
    lock (logLock)
    {
        Console.Out.WriteLine(line);
        Console.Out.Flush();
        try
        {
            var dir = Path.GetDirectoryName(logFile);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.AppendAllText(logFile, line + "\n");
        }
        catch { /* /logs not mounted: stdout still has the line */ }
    }
});

// 2. Method override: the framework's HttpMethodOverrideMiddleware. One instance reads only one
//    source (FormFieldName set => form field only, else X-HTTP-Method-Override header only), so
//    two instances are registered to honour both, form field first.
if (overrideOn)
{
    app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = "_method" });
    app.UseHttpMethodOverride();
}

// 3. Routing must run AFTER the override, otherwise WebApplication inserts UseRouting at the
//    start of the pipeline and endpoint selection would use the raw method.
app.UseRouting();

async Task<IResult> Op(HttpContext ctx, string opId, string template, Dictionary<string, string> pathParams)
{
    ctx.Items["op_id"] = opId;
    ctx.Items["route_template"] = template;
    ctx.Items["path_params"] = pathParams;
    if (viewMac is not null) // D-B: X-Verified-View must match the view this executor dispatched on
    {
        var r = viewMac.Check(ctx.Request.Headers["X-Verified-View"].Select(v => v ?? "").ToList(),
                              ctx.Request.Headers["DPoP"].Select(v => v ?? "").ToList(), ctx.Request.Method, template, pathParams, pathmapRules(), defenceWildcards);
        if (!r.Ok)
        {
            ctx.Items["denied"] = true;
            ctx.Response.Headers.WWWAuthenticate = "DPoP error=\"invalid_token\"";
            return Results.Json(new Dictionary<string, object?> { ["op_id"] = opId, ["framework"] = framework, ["denied"] = true, ["reason"] = r.Reason }, jsonOpts, statusCode: 401);
        }
    }
    if (verifyMode != "off")
    {
        string method, uri;
        if (verifyMode == "origin-routed")
        {
            method = ctx.Request.Method;
            var _r = pathmapRules();
            if (_r is null) { uri = template; foreach (var kv in pathParams) uri = uri.Replace("{" + kv.Key + "}", EncSegment(kv.Value)); }
            else uri = Bench.Defence.ViewMac.ToPublic(Bench.Defence.ViewMac.SubstitutePm(template, pathParams, defenceWildcards), _r);
        }
        else
        {
            method = (string)ctx.Items["raw_method"]!;
            uri = (string)ctx.Items["raw_target"]!;
        }
        bool allow;
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get, verifierUrl);
            req.Headers.TryAddWithoutValidation("X-Original-Method", method);
            req.Headers.TryAddWithoutValidation("X-Original-URI", uri);
            req.Headers.TryAddWithoutValidation("X-Original-Host", ctx.Request.Headers.Host.ToString());
            if (ctx.Request.Headers.TryGetValue("Authorization", out var a)) req.Headers.TryAddWithoutValidation("Authorization", a.ToString());
            if (ctx.Request.Headers.TryGetValue("DPoP", out var d)) req.Headers.TryAddWithoutValidation("DPoP", d.ToString());
            using var resp = await http.SendAsync(req);
            allow = resp.IsSuccessStatusCode;
        }
        catch { allow = false; } // fail closed
        if (!allow)
        {
            ctx.Items["denied"] = true;
            return Results.Json(new Dictionary<string, object?> { ["op_id"] = opId, ["framework"] = framework, ["denied"] = true }, jsonOpts, statusCode: 401);
        }
    }
    return Results.Json(new Dictionary<string, object?>
    {
        ["op_id"] = opId, ["framework"] = framework, ["method"] = ctx.Request.Method, ["path_params"] = pathParams
    }, jsonOpts);
}

Dictionary<string, string> P(string k, string v) => new() { [k] = v };
var none = () => new Dictionary<string, string>();

// NB: handlers taking only HttpContext carry an explicit Task<IResult> return type; otherwise
// the lambda binds to the RequestDelegate overload and the IResult is silently discarded.
var v1 = app.MapGroup("/api/v1");
v1.MapGet("/accounts", Task<IResult> (HttpContext c) => Op(c, "listAccounts", "/api/v1/accounts", none()));
v1.MapGet("/accounts/{id}", (HttpContext c, string id) => Op(c, "getAccount", "/api/v1/accounts/{id}", P("id", id)));
v1.MapPut("/accounts/{id}", (HttpContext c, string id) => Op(c, "updateAccount", "/api/v1/accounts/{id}", P("id", id)));
v1.MapDelete("/accounts/{id}", (HttpContext c, string id) => Op(c, "deleteAccount", "/api/v1/accounts/{id}", P("id", id)));
// G1 query dispatch: idiomatic [FromQuery] binding of `op`.
v1.MapPost("/accounts/{id}/actions", (HttpContext c, string id, string? op) =>
    Op(c, op == "freeze" ? "accountAction.freeze" : op == "close" ? "accountAction.close" : "accountAction.unknown",
       "/api/v1/accounts/{id}/actions", P("id", id)));
v1.MapPost("/transfers", Task<IResult> (HttpContext c) => Op(c, "createTransfer", "/api/v1/transfers", none()));
// G1 body dispatch: the raw body is parsed as JSON whatever the Content-Type.
v1.MapPost("/graphql", async (HttpContext c) =>
{
    string? name = null;
    try
    {
        using var reader = new StreamReader(c.Request.Body);
        var text = await reader.ReadToEndAsync();
        if (JsonNode.Parse(text)?["operationName"] is JsonValue v && v.TryGetValue<string>(out var s)) name = s;
    }
    catch { }
    return await Op(c, name == "getProfile" ? "graphql.getProfile" : name == "deleteProfile" ? "graphql.deleteProfile" : "graphql.unknown",
                    "/api/v1/graphql", none());
});
v1.MapGet("/me", Task<IResult> (HttpContext c) => Op(c, "me", "/api/v1/me", none()));
v1.MapGet("/admin/users", Task<IResult> (HttpContext c) => Op(c, "adminListUsers", "/api/v1/admin/users", none()));
v1.MapDelete("/admin/users/{id}", (HttpContext c, string id) => Op(c, "adminDeleteUser", "/api/v1/admin/users/{id}", P("id", id)));
v1.MapGet("/health", Task<IResult> (HttpContext c) => Op(c, "health", "/api/v1/health", none()));
v1.MapGet("/public/{file}", (HttpContext c, string file) => Op(c, "publicFile", "/api/v1/public/{file}", P("file", file)));

if (routesV2)
{
    // POST sharing the /accounts/{id} path with GET/PUT/DELETE (HttpMethodOverrideMiddleware is POST-only).
    v1.MapPost("/accounts/{id}", (HttpContext c, string id) => Op(c, "postAccount", "/api/v1/accounts/{id}", P("id", id)));
    v1.MapGet("/accounts/{id}/statements", (HttpContext c, string id) => Op(c, "getStatements", "/api/v1/accounts/{id}/statements", P("id", id)));
    v1.MapDelete("/accounts/{id}/statements/{sid}", (HttpContext c, string id, string sid) =>
        Op(c, "deleteStatement", "/api/v1/accounts/{id}/statements/{sid}", new Dictionary<string, string> { ["id"] = id, ["sid"] = sid }));
    // Catch-all: ASP.NET routing {*path} binds the remainder (incl. '/').
    v1.MapGet("/files/{*path}", (HttpContext c, string path) => Op(c, "catchAllFile", "/api/v1/files/{path}", P("path", path)));
}

// /api/v2 as a route group (MapGroup prefix).
var v2 = app.MapGroup("/api/v2");
v2.MapGet("/accounts/{id}", (HttpContext c, string id) => Op(c, "getAccountV2", "/api/v2/accounts/{id}", P("id", id)));

app.Run();
