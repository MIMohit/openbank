# bh-exec-spring: bench API executor in Spring Boot (W5)

The CONTRACT §3 bench API, built on Spring Boot / Spring MVC on embedded Tomcat. Image `bh-exec-spring:latest`, listening on 8080.

## Versions (read from the built image)
| component | version |
|---|---|
| Spring Boot | 3.5.16 (`spring-boot-starter-parent`) |
| Spring Framework (spring-web, spring-webmvc) | 6.2.19 |
| Embedded Tomcat (tomcat-embed-core) | 10.1.55 |
| Jackson databind | 2.21.4 |
| JVM | Eclipse Temurin OpenJDK 21.0.13 (runtime `eclipse-temurin:21.0.13_9-jre-noble`; build `maven:3.10.0-eclipse-temurin-21`) |

The JVM runs with `-Xmx256m -XX:+UseSerialGC`. RSS is about 200 MB.

## Build / run / test
```sh
cd binding/harness/executors/spring
docker build -t bh-exec-spring:latest .            # multi-stage; no local JDK needed
docker run -d --name w5-spring -p 127.0.0.1:18080:8080 -e OVERRIDE=on -e VERIFY_MODE=off \
  -v $PWD/logs:/logs bh-exec-spring:latest
# full 6-config conformance matrix (any W5 framework), then the report:
cd .. && bash spring/tools/w5_conformance.sh spring && python3 spring/tools/w5_report.py spring
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `spring`), `VERIFIER_URL` (default `http://verifier:9100/authz/orig`), `LOG_FILE` (default `/logs/executor.jsonl`).
Results: [CONFORMANCE.md](CONFORMANCE.md).

### Shared W5 tools (`spring/tools/`, used for all four W5 frameworks)
- `w5_conformance.sh <fw>` runs W4's `conformance/run_conformance.py` in all 6 `OVERRIDE`×`VERIFY_MODE` configurations. W4's `stub_verifier.py` runs as docker container `w5-verifier` (alias `verifier`) on network `w5-net`, and the executor is `w5-exec-<fw>` on host port 18580. Everything is torn down afterwards. Output goes to `<fw>/conformance-out/`.
- `normalisation_probes.py <host> <port> --json F --label L` sends raw-socket router-normalisation, dispatch and override probes (they are evidence, not pass/fail).
- `w5_report.py <fw>` generates `<fw>/CONFORMANCE.md` from the raw outputs.

## Implementation
- `V1Controller` (`@RequestMapping("/api/v1")`) and `V2Controller`. **`/api/v2` mount:** `V2Controller` carries the `@V2Api` marker, and `WebConfig.configurePathMatch` applies `PathMatchConfigurer#addPathPrefix("/api/v2", HandlerTypePredicate.forAnnotation(V2Api.class))`, Spring MVC's prefix mechanism for a group of handlers. The handler mapping itself is relative (`/accounts/{id}`).
- G1 query dispatch uses the idiomatic `@RequestParam("op")`, which reads the servlet parameter map: query **and** form body. G1 body dispatch reads the raw body with Jackson whatever the Content-Type.
- `CaptureFilter` runs at `HIGHEST_PRECEDENCE`, before Boot's `OrderedHiddenHttpMethodFilter`, which has order -10000. It records the raw method and the raw target `getRequestURI()+"?"+getQueryString()`; Tomcat's `getRequestURI()` is the undecoded request-line path, `;params` included. After the chain it writes the log line. `EffectiveMethodFilter` runs at `LOWEST_PRECEDENCE` and records the method that the DispatcherServlet routes on.
- NOT_FOUND: `spring.web.resources.add-mappings=false`. `BenchErrors` (`@RestControllerAdvice`) maps `NoHandlerFoundException`, `NoResourceFoundException`, `HttpRequestMethodNotSupportedException` (405) and `HttpMediaTypeNotSupportedException` to 404 `NOT_FOUND`.
- VERIFY_MODE: `Bench.enter()` is called first in every handler, after routing. It calls the verifier with `java.net.http`, uses a 3 s connect timeout and a 5 s request timeout, and fails closed.

## Method override (`OVERRIDE`)
**Mechanism:** Spring's `org.springframework.web.filter.HiddenHttpMethodFilter`, enabled through Spring Boot's documented property `spring.mvc.hiddenmethod.filter.enabled`. The property is off by default since Boot 2.2. `App.main` sets it to `true` exactly when `OVERRIDE=on`. Spring Boot 3.5 evaluates the property with a boolean condition, so `on`/`off` are mapped in code. No custom override code exists.
- Semantics (javadoc, and `strings` on the shipped `spring-web-6.2.19.jar` class): only for **POST**. It reads `request.getParameter("_method")` and accepts the value only if it is PUT, DELETE or PATCH; the value is upper-cased. The current javadoc for Spring Framework 7.1 adds QUERY; 6.2 does not. https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/HiddenHttpMethodFilter.html
- **`X-HTTP-Method-Override` is NOT supported natively.** Spring has no built-in header-based override filter in Spring MVC, and the javadoc mentions no header. We therefore do not add one, per the CONTRACT rule of no custom code. Observed: POST + header DELETE gives 404 NOT_FOUND.
- **Measured G1-relevant facts** (probes, OVERRIDE=on):
  - Because `getParameter` merges the query string and the form body (Servlet spec), **`POST …?_method=DELETE` with a JSON body is also overridden**, yielding 200 deleteAccount.
  - `_method=GET` is refused (404). `_method=delete` becomes DELETE.
  - When both a form `_method=PUT` and the header are sent, the result is PUT, because the header is ignored.
- See CONFORMANCE.md for why W4's header-only verify probe "fails" on Spring (expected), and for the equivalent `_method` check that passes.

## Router normalisation semantics
Observed with `tools/normalisation_probes.py`; raw data is in `conformance-out/probes_ov*.{md,json}`.

| input | result | source |
|---|---|---|
| `%2F` / `%2f` in `{id}` | **400** from Tomcat before Spring runs; no log line | Tomcat connector `encodedSolidusHandling`, default `reject` (https://tomcat.apache.org/tomcat-10.1-doc/config/http.html) |
| `%61ccounts` (encoded unreserved character in a literal segment) | 200 getAccount (decoded before matching) | |
| `;x=1` matrix params | **Stripped for matching**. `/api/v1/accounts;x=1/acc-alice-1` → getAccount, `{id};x=1` → `id=acc-alice-1`, and **`DELETE /api/v1/admin;x=1/users/u-1` → adminDeleteUser**, which is a G2 differential against any prefix-matching gateway or verifier | Spring's PathPatternParser matches on path segments without their parameters (matrix variables page: https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/matrix-variables.html) |
| trailing slash (`/accounts/`, `/accounts/{id}/`) | **404**. Trailing-slash match is off by default since Spring Framework 6.0 | Spring Framework 6.0 release notes (https://github.com/spring-projects/spring-framework/wiki/Spring-Framework-6.0-Release-Notes) |
| `//` (leading or in the middle) | 404 | |
| `/../`, `%2e%2e`, `/./` | 404. Matching uses the raw `requestURI`, so dot segments are not resolved for routing | observed; not documented explicitly |
| case (`/ACCOUNTS`, `/API`, `/api/V2`) | 404 (case-sensitive) | |
| `.json` suffix on `{id}` | kept in the param (`id=acc-alice-1.json`). No suffix-pattern matching (removed in 6.0) | |
| `\` or `%5C` | 400 from Tomcat | `allowBackslash` default false (Tomcat connector doc) |
| `%00`, `#frag` in the target | 400 from Tomcat | |
| `%3F` in `{id}` | decoded into the param (`acc?x`) | |
| absolute-form target | routed by path (200 me) | |
| lower-case method `get` | 404. The method token is case-sensitive and no `get` handler exists | |
| HEAD / OPTIONS | 200, handled implicitly by Spring MVC; `op_id` from the GET handler (HEAD) or NOT_FOUND (OPTIONS) | |
| `?op=freeze&op=close` | `accountAction.unknown`. `@RequestParam String` joins duplicates as `"freeze,close"` | |
| `?op[]=close` | 400. Tomcat rejects `[` `]` in the query (`relaxedQueryChars`) | |
| `op=close` in the form body, no query | **accountAction.close** (servlet params include the form body) | |
| `?op=freeze` + form body `op=close` | unknown (joined as `"freeze,close"`) | |
| `op` in a JSON body | unknown | |
| graphql duplicate `operationName` keys | the last key wins (Jackson): deleteProfile | |

## Contract interpretations
W4's 12 interpretations (conformance/README.md) are applied. In particular: method mismatch is NOT_FOUND (#1); framework-native responses are kept (#2); requests rejected by Tomcat produce no log line (#3); the verifier is called only for matched ops (#4); fail closed (#5); the origin-routed encoding is `quote(v, safe="-._~!$&'()*+,;=:@")` (#6). Spring-specific choices:
- `raw_target` is `getRequestURI()` + `?` + `getQueryString()`. This is byte-exact for origin-form. For absolute-form, Tomcat reports only the path.
- `effective_method` is the method that the DispatcherServlet saw. That is the request wrapped by HiddenHttpMethodFilter, captured by the innermost filter.

## Known limitations
- No header method override exists, by design (see above). The paper should treat Spring as a "`_method` param only, query included" framework.
- Requests that Tomcat rejects (400 for `%2F`, `\`, `%00`, `#`, `[ ]`) never reach Spring, so no JSONL line is written (interpretation #3).
