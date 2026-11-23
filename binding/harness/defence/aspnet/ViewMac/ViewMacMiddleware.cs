using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;

namespace Bench.Defence;

/// ASP.NET Core adapter. Must run AFTER UseRouting() (endpoint and route values are selected) and
/// after UseHttpMethodOverride() (Request.Method is the effective method), BEFORE the endpoint runs.
public static class ViewMacMiddleware
{
    public const string ItemKey = "bench.viewmac";

    /// Full template of the matched endpoint in {name} form, rebuilt from the parsed pattern
    /// (MapGroup prefixes included, constraints/defaults/catch-all markers dropped).
    public static string? Template(RouteEndpoint? ep)
    {
        if (ep is null) return null;
        var sb = new System.Text.StringBuilder();
        foreach (var seg in ep.RoutePattern.PathSegments)
        {
            sb.Append('/');
            foreach (var part in seg.Parts)
            {
                switch (part)
                {
                    case RoutePatternLiteralPart l: sb.Append(l.Content); break;
                    case RoutePatternSeparatorPart s: sb.Append(s.Content); break;
                    case RoutePatternParameterPart p: sb.Append('{').Append(p.Name).Append('}'); break;
                }
            }
        }
        return sb.Length == 0 ? "/" : sb.ToString();
    }

    public static ViewMacResult Evaluate(ViewMac vm, HttpContext ctx, string template, IReadOnlyDictionary<string, string> p) =>
        vm.Check(ctx.Request.Headers[ViewMac.Header].Select(v => v ?? "").ToList(),
                 ctx.Request.Headers["DPoP"].Select(v => v ?? "").ToList(),
                 ctx.Request.Method, template, p);

    public static Dictionary<string, string> RouteParams(HttpContext ctx, RouteEndpoint ep) =>
        ep.RoutePattern.Parameters.ToDictionary(p => p.Name, p => Convert.ToString(ctx.Request.RouteValues[p.Name], System.Globalization.CultureInfo.InvariantCulture) ?? "");

    /// app.UseRouting(); app.UseViewMac(key);   Unmatched requests pass through untouched (404 later).
    public static IApplicationBuilder UseViewMac(this IApplicationBuilder app, byte[] key)
    {
        var vm = new ViewMac(key);
        return app.Use(async (ctx, next) =>
        {
            if (ctx.GetEndpoint() is not RouteEndpoint ep) { await next(ctx); return; }
            var r = Evaluate(vm, ctx, Template(ep)!, RouteParams(ctx, ep));
            ctx.Items[ItemKey] = r;
            if (r.Ok) { await next(ctx); return; }
            ctx.Response.StatusCode = 401;
            ctx.Response.Headers.WWWAuthenticate = "DPoP error=\"invalid_token\"";
            await ctx.Response.WriteAsJsonAsync(new Dictionary<string, string> { ["error"] = "view_binding", ["reason"] = r.Reason });
        });
    }
}
