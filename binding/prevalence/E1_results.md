# E1: how often a (method, path) view maps to more than one operation (G1 prevalence)

Worker W8. Every number in this file comes from a script in `binding/prevalence/e1/` (outputs in `e1/out/`) or from a cited source. To regenerate, run the commands in §8.

## 1. Question and unit of analysis

A DPoP proof binds `htm` (method) and `htu` (scheme, authority and path, with **no query and no fragment**, RFC 9449 §4.2/§4.3). So the verifier's view of a request is the key **K = (METHOD, path)**. A **binding collision** is a key K that the API description maps to **two or more semantically different operations**, where the operation is selected by something outside K: a query parameter, a header, or a body field. In that case one accepted proof does not determine `op(π)` (G1, under-binding by design).

- **Corpus:** the APIs.guru `openapi-directory`, shallow clone at commit `f04b8d0bcd39c52e1cf3ad7a5fe744709832ae49` (committed 2026-04-20T15:54:01+03:00), cloned 2026-11-22. We also used the `https://api.apis.guru/v2/list.json` snapshot from the same day. Both live in `data/`, which is gitignored.
- **Unit:** one spec per API. We use the APIs.guru `preferred` version from list.json, and fall back to the last version directory for 225 APIs that are not in list.json. §6 (T8) reports the every-file count as a sensitivity check.
- **Operation:** one (method, path-key) entry with method ∈ {get, put, post, delete, options, head, patch, trace}. **State-changing** means POST, PUT, PATCH or DELETE.

## 2. Detectors (`e1/analyze.py`)

| id | mechanism | strong-tier rule (counted) | weak tier (reported only, not counted) |
|---|---|---|---|
| M1 | query or fragment in the path key | ≥2 operations whose OpenAPI path keys normalise to the same path once everything after `?` or `#` is cut (e.g. AWS `/#Action=X`, `/#X-Amz-Target=Y`, Flickr `/rest?method=…`) | none |
| M2 | dispatch parameter | a query, form or header parameter whose name is a dispatcher name (`action, op, operation, cmd, command, method, func, do, task, verb, call, rpc, request, actiontype, …`) AND whose enum has ≥2 values | same name without an enum |
| M3 | header dispatch | a header parameter `X-Amz-Target`, `SOAPAction`, `X-Goog-*Method*`, `X-Target`, `X-Action` or `X-Operation` with ≥2 values | single value |
| M4 | body discriminator | a request body that is a `oneOf`/`anyOf` with ≥2 branches and a `discriminator`, OR a top-level body property named like a dispatcher whose enum has ≥2 values | `oneOf` without a discriminator |
| M5 | RPC single endpoint | a body schema with `jsonrpc`+`method`, or `query`+`variables`/`operationName` (GraphQL) | path heuristic only (`/graphql`, `/rpc`, …) |
| OVR | documented method override | an `X-HTTP-Method-Override`/`X-HTTP-Method`/`X-Method-Override` header parameter or a `_method` parameter **on a POST**, or override text in a description | none |

A key K counts as collided if at least one strong-tier flag falls on it. "Ops in collided keys" counts every spec operation on such a key.

## 3. Corpus (T1)

- Spec files found: **4,138**. Parsed: **4,105**. Failed: **33**, all YAML `ParserError` (listed in `e1/out/e1_parse_errors.csv`). Another 2 files parsed only after tab or C1-control-character repair.
- Distinct API ids: 2,658, of which **2,652** have at least one parsed version. That is the denominator. list.json has 2,529 entries.
- Spec versions in the chosen set: 984 Swagger 2.0 and 1,668 OpenAPI 3.x.
- The chosen set has **127,642 operations**, of which **66,184 are state-changing**.

## 4. Raw detector results (strong tier, before validation)

### T2 Headline (95% Wilson CIs, `analysis/stats.py`)

| subset | APIs | operations | state-changing ops | APIs with ≥1 collided key | APIs with ≥1 state-changing collided key | ops in collided keys | state-changing ops in collided keys |
|---|---|---|---|---|---|---|---|
| all | 2652 | 127642 | 66184 | 234 (8.8% [7.8, 10.0]) | 225 (10.9% [9.6, 12.3] of 2063 APIs with state ops) | 9420 (7.4% [7.2, 7.5]) | 7577 (11.4% [11.2, 11.7]) |
| excluding amazonaws.com | 2298 | 112078 | 54552 | 66 (2.9% [2.3, 3.6]) | 58 (3.4% [2.6, 4.4] of 1709) | 305 (0.3% [0.2, 0.3]) | 197 (0.4% [0.3, 0.4]) |
| excl. amazonaws/azure/googleapis/microsoft | 1329 | 63370 | 29700 | 47 (3.5% [2.7, 4.7]) | 42 (4.5% [3.4, 6.1] of 928) | 252 (0.4% [0.4, 0.4]) | 149 (0.5% [0.4, 0.6]) |
| finance (category financial or payment) | 106 | 4645 | 2404 | 4 (3.8% [1.5, 9.3]) | 4 (4.9% [1.9, 12.0] of 81) | 9 (0.2% [0.1, 0.4]) | 9 (0.4% [0.2, 0.7]) |
| health (title/id keyword) | 15 | 332 | 252 | 2 (13.3% [3.7, 37.9]) | 2 (14.3% [4.0, 39.9] of 14) | 39 (11.7% [8.7, 15.7]) | 39 (15.5% [11.5, 20.5]) |

### T3 Per mechanism

| mechanism | APIs | collided keys | state-changing keys | flagged ops | of which AWS ops | APIs excl. AWS |
|---|---|---|---|---|---|---|
| M1 query-in-path | 168 | 256 | 202 | 9227 | 9102 | 8 |
| M2 dispatch-param | 20 | 34 | 21 | 34 | 1 | 19 |
| M3 header-dispatch | 0 | 0 | 0 | 0 | 0 | 0 |
| M4 body-discriminator | 51 | 156 | 156 | 156 | 12 | 43 |
| M5 RPC endpoint | 3 | 3 | 3 | 3 | 0 | 3 |

- **M1 sub-types:** 5,558 ops are `X-Amz-Target` encoded as `#fragment` (129 APIs); 3,549 are `Action=` query encoded as `#fragment` (34 APIs); 75 are a literal `?query` (5 APIs); 45 are the base op of a query-variant group (12 APIs).
- **M3 is 0** because this corpus encodes AWS's `X-Amz-Target` dispatch in the path key (`/#X-Amz-Target=…`), so M1 catches it instead. No spec documents `X-Amz-Target`/`SOAPAction` as a multi-valued header parameter.
- **Weak tier (not counted):** 672 ops in 89 APIs (M4 567, M2 103, M3 2).
- **Documented method override (T5):** 6 of 2,652 APIs (0.2% [0.1, 0.5]). All six are Amadeus travel APIs that document `X-HTTP-Method-Override` as a header on a POST search endpoint (e.g. `POST /shopping/flight-offers`).
- **GraphQL / JSON-RPC single endpoints, strong tier (T6):** 3 APIs: `mastercard.com:MAWS` (POST /v1/maws), `nebl.io` (POST /) and `redhat.com:catalog_inventory` (POST /graphql). The directory is an OpenAPI corpus, so GraphQL-first APIs are largely absent. This number is not an estimate of GraphQL prevalence.

### T4 By domain (selection; full table in `e1/out/e1_tables.md` and `e1/out/e1_by_category.csv`)

| category | APIs | APIs with a collided key | state ops | state ops in collided keys |
|---|---|---|---|---|
| cloud | 1039 | 176 (16.9% [14.8, 19.3]) | 16843 | 7407 (44.0% [43.2, 44.7]) |
| media | 360 | 14 (3.9%) | 4667 | 16 (0.3%) |
| open_data | 319 | 2 (0.6%) | 1223 | 4 (0.3%) |
| analytics | 302 | 13 (4.3%) | 4037 | 16 (0.4%) |
| developer_tools | 168 | 8 (4.8%) | 27395 | 42 (0.2%) |
| FINANCE (financial or payment) | 106 | 4 (3.8% [1.5, 9.3]) | 2404 | 9 (0.4%) |
| telecom | 61 | 3 (4.9%) | 1197 | 18 (1.5%) |
| enterprise | 14 | 5 (35.7% [16.3, 61.2]) | 2064 | 31 (1.5%) |
| HEALTH (keyword) | 15 | 2 (13.3% [3.7, 37.9]) | 252 | 39 (15.5%) |

The two "health" APIs with collisions are `amazonaws.com:comprehendmedical`, a medical NLP service with 26 operations on POST / selected by X-Amz-Target, and `amazonaws.com:health`, the AWS service-health API, which the keyword rule misclassifies as a medical API. For healthcare, see the FHIR analysis in §7.1, which is more informative.

## 5. Hand validation and precision

**Design (`e1/sample.py`).** The seed is `20261123`. We drew 100 strong-tier flagged operations from the chosen set, **stratified by mechanism** (allocation M1 30, M2 30, M4 37, M5 3; M3 is empty). We stratified because M1 makes up 98% of flags, so a uniform sample would almost all be AWS. The sampled rows and the spec context we judged from are in `e1/out/validation_sample.csv`. The judge (W8) read the operation summary, description, parameters, enums and sibling operations, and opened the spec file where that was not enough (for example the Visma, Mastercard, Zuora and Stripe schemas). Verdicts and one-line rationales are in `e1/validation_judgments.csv`.

- **TP:** the key carries ≥2 operations with different effects (distinct verbs or commands such as delete vs trash, approve vs reject, or distinct AWS actions), selected only by the flagged value.
- **FP:** the flagged value is data (a payment method, a rule's allow/deny attribute), a list filter, a computation option, or a polymorphic body of one operation.
- **UNCLEAR:** the spec text does not settle it. Unclear cases count as FP in the headline precision.

**T9 Precision (`e1/precision.py` → `e1/out/precision.csv`).**

| stratum | flagged ops (population) | sampled | TP | FP | unclear | precision [95% Wilson CI] |
|---|---|---|---|---|---|---|
| M1 query-in-path | 9227 | 30 | 30 | 0 | 0 | **1.00** [0.89, 1.00] |
| M2 dispatch-param | 34 | 30 | 12 | 18 | 0 | **0.40** [0.25, 0.58] |
| M4 body-discriminator | 156 | 37 | 11 | 25 | 1 | **0.30** [0.17, 0.46] |
| M5 RPC endpoint | 3 | 3 | 2 | 1 | 0 | 0.67 [0.21, 0.94] |
| all, unweighted sample | 9420 | 100 | 55 | 44 | 1 | 0.55 [0.45, 0.64] |
| all, stratum-weighted | 9420 | 100 | | | | **0.986** (≈9,289 true flagged ops) |
| non-M1 (M2+M4+M5), unweighted | 193 | 70 | 25 | | | 0.36 [0.26, 0.47] |
| non-M1, stratum-weighted | 193 | | | | | 0.32 (≈62 true flagged ops) |

**Supplementary censuses (every flag, not a sample):**

- **Finance (`e1/finance_census_judgments.csv`): 4 of 9 flagged ops are TP**, in 2 of 106 finance APIs.
  - `stripe.com` POST /v1/subscription_items/{id}/usage_records: `action=increment|set` adds to usage or overwrites it.
  - `zuora.com` POST /objects/jobs: `operation=delete|create`.
  - `zuora.com` POST /v1/payment-methods/{id}/profiles: `action=Activate|Persist`. Activate also sends a cardholder-initiated transaction to the gateway.
  - `zuora.com` POST /v1/refunds/{id}/reconcile: `action=settle|reject`.
  - The flags on `rebilly.com` (polymorphic KYC documents), `sinao.app` (`method` is the payment method) and Stripe payouts (`method=instant|standard`) are FPs.
- **Non-AWS M1 (`e1/nonaws_m1_census_judgments.csv`, API-level), 4 of 8 APIs TP.**
  - TPs: `box.com`, `flickr.com` (22 methods on GET /rest), `osisoft.com` and `formapi.io`.
  - FPs: `weatherbit.io` (alternative selectors for one read), `opensuse.org:obs` `?view=` and `azure.com:hdinsight-job` (variants of one read).
  - `mastercard.com:masterpassqr` is a **detector artefact**: `#env` is a templated path segment (`/send/#env/v1/...`), so cutting at `#` wrongly merges distinct paths. Its 3 state ops in T7 are therefore spurious.

**Hand-confirmed lower bound (`e1/confirmed.py` → `e1/out/confirmed_apis.csv`).** **44 of 2,652 APIs** have at least one collision that a person checked against the spec text: 25 AWS APIs and **19 of 2,298 non-AWS APIs** (0.8%). The non-AWS ones are:
- **Finance:** stripe.com, zuora.com, fraudlabspro.com (order feedback `APPROVE|REJECT|REJECT_BLACKLIST`), loket.nl (payroll tax return `confirm|cancel`)
- **Collaboration and cloud:** zoom.us (`DELETE /users/{id}?action=disassociate|delete`, recordings `trash|delete`), azure.com:storage-DataLakeStorage (`PATCH ?action=append|flush|setProperties|setAccessControl`), box.com, digitalocean.com (`POST /v2/volumes/actions` `type=attach|detach`), microsoft.com:graph-beta
- **Others:** enode.io (EV charger `START|STOP`), mist.com, opensuse.org:obs (`POST /person/{login}?cmd=change_password|lock|delete`), instagram.com, sms77.io, flickr.com, osisoft.com, formapi.io, redhat.com:catalog_inventory (GraphQL), nebl.io (JSON-RPC)

**Interpretation.**
1. Collisions are concentrated, not rare. Across the whole corpus, **11.4% of state-changing operations sit on a collided (method, path) key**, and the validated precision of that bulk (M1) is 30/30. This share comes almost entirely from AWS's query and RPC-style protocols, which pack hundreds of operations onto `POST /` or `GET /`; EC2 alone has 594 operations on each.
2. Outside AWS, under-binding by design is real but uncommon in OpenAPI descriptions. 2.9% of non-AWS APIs are flagged. The true share lies between the hand-confirmed lower bound of 0.8% and that raw 2.9%. M2 and M4 precision is 0.30–0.40, which pushes it toward the lower end. When collisions do occur they hit high-impact commands: delete vs disassociate a user, settle vs reject a refund, change_password vs lock vs delete a person, start vs stop a charger.
3. Documented method override is very rare in API descriptions (6/2,652, all Amadeus). Override is a framework property, not something an API advertises (see E2), so the spec corpus cannot measure it.

## 6. Sensitivity (T8: every parsed spec file, all versions)

| subset | spec files | operations | state ops | files with a collided key | state ops in collided keys |
|---|---|---|---|---|---|
| all files | 4105 | 156729 | 81710 | 261 (6.4% [5.7, 7.1]) | 7871 (9.6% [9.4, 9.8]) |
| all files excl. AWS | 3736 | 140362 | 69632 | 81 (2.2% [1.7, 2.7]) | 212 (0.3% [0.3, 0.3]) |

The conclusions do not depend on the version-selection rule.

## 7. Named specifications

### 7.1 HL7 FHIR (R5 http.html, plus the HAPI FHIR public R4 server's CapabilityStatement)

Inputs are fetched by `e1/fetch_named.sh` and analysed by `e1/named_fhir.py`. HAPI metadata was fetched 2026-11-22T18:55:05Z from `https://hapi.fhir.org/baseR4/metadata`: software "HAPI FHIR Server 8.13.10-SNAPSHOT", fhirVersion 4.0.1. Line numbers refer to our text extraction `data/named/fhir_r5_http.txt` of https://hl7.org/fhir/R5/http.html.

FHIR defines several interactions whose target or effect is selected outside (method, path):

| FHIR interaction | wire form | what selects the operation or target | covered by DPoP htm/htu? |
|---|---|---|---|
| conditional update | `PUT [base]/[type]?[search parameters]` (txt L958) | the query selects which resource is overwritten, or causes a create | no (query) |
| conditional delete | `DELETE [base]/[type]?[search parameters]` (txt L1233) | the query selects which resources are deleted, possibly many | no |
| conditional patch | `PATCH [base]/[type]?[search]` (txt L1094) | the query | no |
| conditional create | `POST [base]/[type]` + header `If-None-Exist: [search parameters]` (txt L1349) | a header turns the create into a no-op | no (header) |
| batch / transaction | `POST [base]` with a Bundle; "Each entry SHALL carry request details (Bundle.entry.request)" (txt L1724-1732) | **every** CRUD on every resource type, selected in the body | no: one key for the whole API |
| search via POST | `POST [base]/[type]/_search` (txt L1447) | parameters in the body | no |
| extended operations | `[base]/[type]/[id]/$op` | the name is in the path, so it IS bound; the parameters are not | partly |

- The R5 http.html text contains **no** mention of `X-HTTP-Method-Override` (0 hits).
- On the HAPI public R4 server, all **146/146** resource types declare `conditionalUpdate=true`, `conditionalCreate=true` and `conditionalDelete=multiple`. The server supports the system-level `transaction` interaction, declares 15 system-level operations and 1,630 type- and instance-level operation declarations, and exposes `$graphql` per type (`e1/out/fhir_capability.csv`).
- **Implication.** A sender-constrained FHIR client's proof for `POST [base]` (a transaction) or `DELETE [base]/Patient?…` names neither which resources nor which interactions execute. In FHIR, under-binding is the normal case built into the standard, not a corner case.

### 7.2 Model Context Protocol (MCP)

Sources are pinned to commit `862397cec702e8f828713071da501cf56158e8fc` of `modelcontextprotocol/modelcontextprotocol`, under `docs/specification/`.

- **2025-11-25 transports** (`basic/transports.mdx` L70-71): "The server MUST provide a single HTTP endpoint path … that supports both POST and GET methods."
- **2026-07-28 Streamable HTTP** (`basic/transports/streamable-http.mdx` L47-48): "a single HTTP endpoint path … that supports POST". Every JSON-RPC request is a POST to that path, including `tools/call`, `resources/read`, `prompts/get`, `initialize` and so on. The operation is chosen by the body `method` and, for tools, `params.name`.
- **2026-07-28** adds the `Mcp-Method` and `Mcp-Name` request headers, which mirror the body `method` and `params.name`/`params.uri` (L286-291). Servers that process the body "MUST reject requests where the values specified in the headers do not match the corresponding values in the request body. This prevents potential security vulnerabilities when different components in the network rely on different sources of truth (e.g., a load balancer routing on the header value while the MCP server executes based on the body value)" (L588-593). On mismatch the server returns 400 / `-32020 HeaderMismatch`.
- **Authorization** (2026-07-28 `basic/authorization/index.mdx` L262-266; 2025-11-25 `basic/authorization.mdx` L451) uses `Authorization: Bearer <access-token>`. The string "DPoP" occurs **0 times** across the 5 fetched MCP spec files.
- **Implication.** MCP collapses every tool invocation onto one (POST, /mcp) key. A DPoP proof, if one were added, would bind only that key and not which tool runs. The 2026 header-mirroring rule is the spec acknowledging the G2 split-view risk, but it constrains only routers that read headers. It does nothing for a proof whose `htu` cannot express the tool. Under our definition MCP is a pure M5 collision.

## 8. Reproduce

```sh
cd binding/prevalence
python3.12 -m venv .venv && .venv/bin/pip install pyyaml numpy scipy
sh e1/fetch_named.sh                       # corpus clone + list.json + FHIR + MCP (into data/)
.venv/bin/python -I e1/analyze.py --root data/openapi-directory/APIs --out e1/out --procs 3
.venv/bin/python -I e1/summarize.py        # T1–T8 -> e1/out/e1_tables.md, e1_api_level.csv, e1_by_category.csv
.venv/bin/python -I e1/sample.py           # seeded sample -> e1/out/validation_sample.csv
.venv/bin/python -I e1/precision.py        # T9 -> e1/out/precision.csv (+ finance census)
.venv/bin/python -I e1/confirmed.py        # hand-confirmed lower bound -> e1/out/confirmed_apis.csv
.venv/bin/python -I e1/named_fhir.py       # FHIR CapabilityStatement -> e1/out/fhir_capability.csv
```

CSVs: `e1_specs.csv` (per file), `e1_api_level.csv` (chosen set), `e1_flags.csv` (every flag with tier and evidence), `e1_by_category.csv`, `e1_parse_errors.csv`, `validation_sample.csv`, `precision.csv`, `confirmed_apis.csv`, `fhir_capability.csv`.

## 9. Limitations

- **Descriptions, not deployments.** A spec may omit dispatch it really performs, which under-counts (e.g. undocumented `_method` support). It may also describe dispatch that a gateway normalises away. A collision means a proof bound to K is ambiguous; it does not mean a deployed API accepts DPoP. Most of these APIs use Bearer, API keys or SigV4; AWS SigV4 signs the query and `X-Amz-Target`, so AWS itself is not vulnerable. AWS here shows how common the protocol pattern is, not that AWS is exploitable.
- **Corpus bias.** APIs.guru over-represents large cloud vendors (AWS has 354 of 2,652 APIs; Azure, Google and Microsoft together have 969) and under-represents GraphQL, gRPC and private APIs (Open Banking, FHIR servers). The cloud stratum dominates the corpus-wide share, which is why we report non-AWS and non-hyperscaler subsets.
- **Precision is per mechanism.** The per-mechanism precision on the large M1 stratum (n=30) comes from AWS-encoded flags. The non-AWS M1 flags were checked only by the API-level census (4/8 TP), and it found one detector artefact (`#env`). M2 and M4 precision is low (0.40 and 0.30), so the raw non-AWS counts in T2 overstate prevalence about 3×; use the precision-adjusted or hand-confirmed figures. The strata for M2 (34) and M5 (3) are small. The Wilson CIs ignore the finite-population correction, so they are conservative.
- **One judge.** There was no second rater, so no inter-rater agreement is reported. Every verdict has a rationale so it can be audited. The borderline rules (filters and attributes are FP; verbs and commands are TP) are stated in §5.
- **Recall is not measured.** We only validated flagged operations, so collisions the detectors miss (dispatch described only in prose, `x-` extensions, multipart parts) are not counted. The numbers are lower bounds on the true incidence in the described APIs.
- **The domain labels are APIs.guru's.** Many APIs have no category (187 "uncategorized"). The health label is a keyword heuristic and misclassifies AWS Health.
- **Parse failures.** 33 of 4,138 files (0.8%) did not parse and are excluded. They include `adyen.com/CheckoutService-v71`, a finance API.
