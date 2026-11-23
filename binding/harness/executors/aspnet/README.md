# bh-exec-aspnet: bench API executor in ASP.NET Core (W5)

The CONTRACT §3 bench API as ASP.NET Core **minimal APIs** on Kestrel. Image `bh-exec-aspnet:latest`, listening on 8080.

## Versions
| component | version |
|---|---|
| ASP.NET Core / .NET runtime | 9.0.23 (`mcr.microsoft.com/dotnet/aspnet:9.0.23`, from `dotnet --list-runtimes` in the image) |
| SDK (build stage) | `mcr.microsoft.com/dotnet/sdk:9.0.321` |
| Server | Kestrel (in-box), HTTP/1.1 on `ASPNETCORE_HTTP_PORTS=8080` |

`DOTNET_gcServer=0` (workstation GC) keeps memory low; RSS is about 60 MB.

## Build / run / test
```sh
cd binding/harness/executors/aspnet && docker build -t bh-exec-aspnet:latest .
docker run -d --name w5-aspnet -p 127.0.0.1:18080:8080 -e OVERRIDE=on -v $PWD/logs:/logs bh-exec-aspnet:latest
cd .. && bash spring/tools/w5_conformance.sh aspnet && python3 spring/tools/w5_report.py aspnet
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `aspnet`), `VERIFIER_URL`, `LOG_FILE`. Results: [CONFORMANCE.md](CONFORMANCE.md) (all 6 configurations pass, with 0 failures).
The shared W5 tools live in `../spring/tools/` (see spring/README.md).

## Implementation (`Program.cs`)
- The pipeline order is explicit:
  1. Outermost `app.Use` captures the raw method and `IHttpRequestFeature.RawTarget`, the request-target exactly as Kestrel received it. After `next()` it maps an unmatched 404/405 to 404 `NOT_FOUND` and writes the log line.
  2. `UseHttpMethodOverride` (only if `OVERRIDE=on`).
  3. `UseRouting()` is called explicitly **after** the override. If it is not, `WebApplication` inserts routing at the start of the pipeline and endpoint selection would use the raw method.
- **`/api/v2` mount:** a route group, `app.MapGroup("/api/v2")`, ASP.NET Core's prefix-group mechanism. `/api/v1` is also a group.
- G1 query dispatch binds `string? op` from the query (minimal-API implicit `[FromQuery]`). Body dispatch reads the raw body with `System.Text.Json` (`JsonNode`) whatever the Content-Type.
- VERIFY_MODE: the verifier is called inside the endpoint (after routing), with `HttpClient`, a 5 s timeout, and fail-closed handling.

## Method override (`OVERRIDE`)
**Mechanism:** the framework's `HttpMethodOverrideMiddleware`, through `app.UseHttpMethodOverride(...)` (package Microsoft.AspNetCore.HttpOverrides, in the shared framework).
- Docs: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.httpmethodoverrideextensions.usehttpmethodoverride. "By default, the X-HTTP-Method-Override request header is used to specify the HTTP method being tunneled." The overload with `HttpMethodOverrideOptions` is described as: "Allows incoming POST request to override method type with type specified in form."
- `HttpMethodOverrideOptions.FormFieldName`: "Denotes the form element that contains the name of the resulting method type. If not set the X-Http-Method-Override header will be used." (https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.httpmethodoverrideoptions.formfieldname)
- One middleware instance therefore reads **one** source. To honour both, as the CONTRACT requires, we register two stock instances, with no custom code: first `FormFieldName="_method"`, then the default (header). Only POST is overridden.
- **Measured** (probes, OVERRIDE=on):
  - The header and form `_method` both work. **`?_method=` in the query is not honoured** (404). A JSON `_method` is not honoured.
  - **The value is not upper-cased or validated.** `X-HTTP-Method-Override: delete` gives `effective_method="delete"`, and routing still matches DELETE because method matching is case-insensitive. `GET` is accepted, so POST→GET works.
  - Form `_method=PUT` plus header `DELETE` gives **PUT**. The form instance runs first, and the second instance then sees a non-POST method. This order is our registration choice.

## Router normalisation semantics
Raw data: `conformance-out/probes_ov*.{md,json}`.

| input | result | source / note |
|---|---|---|
| `%2F` / `%2f` in `{id}` | **matches**, and the param keeps the encoding (`id="acc%2Falice"`). Kestrel decodes every escape except `%2F` | routing doc: "Route parameters are not always URL decoded" (https://learn.microsoft.com/en-us/aspnet/core/fundamentals/routing) |
| `%61ccounts` | 200 getAccount (decoded) | "Text matching is case-insensitive and based on the decoded representation of the URL's path." (same doc) |
| `/../`, `%2e%2e`, `/./` | **resolved by Kestrel** before routing: `/api/v1/admin/../accounts/x` → getAccount, **`/api/v2/../v1/admin/users` → adminListUsers** | observed. Kestrel normalises dot segments in the decoded path. `raw_target` keeps the original |
| `;x=1` | not special. In a literal segment the result is 404; in `{id}` it stays in the value (`acc-alice-1;x=1`) | |
| trailing slash | **matches** (`/accounts/` → listAccounts, `/accounts/{id}/` → getAccount) | observed |
| `//` | 404 | |
| case (`/ACCOUNTS`, `/API`, `/api/V2`) | **matches** (case-insensitive) | routing doc (quoted above) |
| `.json` suffix | kept in `{id}` | |
| `\`, `%5C` | 404 | |
| `%00`, `#frag` | 400 from Kestrel; no log line | |
| absolute-form | routed by path (200 me) | |
| lower-case method `get` | **200 getAccount**. Kestrel accepts the token and HTTP-method matching is case-insensitive. `raw_method`/`effective_method` are logged as `get` | observed |
| HEAD / OPTIONS | 404 NOT_FOUND. Minimal APIs register no implicit HEAD/OPTIONS | |
| `?op=freeze&op=close` | unknown (multiple values bind as `"freeze,close"`) | |
| `?op[]=close` | unknown | |
| `op` in the form or JSON body | unknown (query binding only) | |
| `?op=freeze` + form `op=close` | **freeze** (query only) | |
| graphql duplicate `operationName` | unknown. `System.Text.Json`'s `JsonObject` throws on a duplicate key, so the input counts as invalid JSON (interpretation #11) | |

## Contract interpretations
W4's interpretations #1–#12 are applied (conformance/README.md). ASP.NET-specific choices:
- `raw_target` = `IHttpRequestFeature.RawTarget`, byte-exact including absolute-form.
- `query` = the substring after the first `?` of the raw target.
- Two override middleware instances are used, form first (see above). With header first, the header would win instead. Neither order is "the" default, because the framework expects one source per instance.

## Known limitations
- Requests that Kestrel rejects (400: `%00`, `#`, malformed request lines) produce no log line (interpretation #3).
