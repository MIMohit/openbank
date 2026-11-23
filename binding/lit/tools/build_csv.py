"""Build screening.csv, extraction.csv and related_matrix.csv for the W1 literature review.

Inputs: the raw search logs in ../search_log/ (arXiv, Crossref, Semantic Scholar API dumps)
plus the hand-curated decisions in CURATED below (decisions taken by reading titles/abstracts
or full texts; see ../killreads.md for full-text evidence).

Run:  python3 -I binding/lit/tools/build_csv.py
"""
import csv, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
LIT = os.path.dirname(HERE)
LOG = os.path.join(LIT, "search_log")

# ---------------------------------------------------------------------------
# Curated records. key -> dict. 'match' = list of arXiv ids / DOIs / title fragments
# used to attach search-log hits to this record (so the record is not auto-excluded).
# stage: TA = title/abstract screen; FT = full text read; MD = metadata/landing page only;
#        SPEC = standard/spec/WG artefact read directly.
# decision: include (extracted) | background (cited, not extracted) | exclude
# ---------------------------------------------------------------------------
C = []
def rec(key, title, authors, venue, year, url, stage, decision, reason, match=(), src="", **ext):
    C.append(dict(key=key, title=title, authors=authors, venue=venue, year=year, url=url,
                  stage=stage, decision=decision, reason=reason, match=list(match), src=src, ext=ext))

# ---- Formal analyses (RQ-L2) ------------------------------------------------
rec("hosseyni2024csf", "Formal Security Analysis of the OpenID FAPI 2.0: Accompanying a Standardization Process",
    "P. Hosseyni; R. Küsters; T. Würtele", "IEEE CSF 2024 (full version IACR ePrint 2024/078)", 2024,
    "https://doi.org/10.1109/CSF61375.2024.00002", "FT", "include",
    "Seed; full text (ePrint 2024/078, 86pp, via Wayback copy) read: RS is atomic process; htu checked against own m.host+m.path; no intermediary",
    match=["10.1109/csf61375.2024.00002"], src="seed;crossref:D2",
    venue_year="CSF'24", layer="protocol (symbolic WIM)", oracle="formal proof of authorization/session-integrity properties",
    binding_involved="DPoP(htm,htu,ath,nonce,cnf.jkt); mTLS", placement_modelled="no (RS = single atomic process; Alg.12 p39 ePrint)",
    primitives="none (no URI normalisation, no method override, no query/body semantics)", targets_versions="FAPI 2.0 drafts (2022-23)",
    threat_model="FAPI 2.0 AM: network attacker + leaks (A5 resource-request leak after processing)", artefact="paper only (pen-and-paper proof)",
    closest_rq="RQ-L2", kill_risk="medium->low (read: model lacks intermediary and operation integrity)",
    notes="reqUri := <URL,S,m.host,m.path,<>,⊥>; resourceID := m.path (same message). Property: attacker cannot derive resource r (confidentiality), not integrity of executed op.")
rec("hosseyni2024tops", "Formal Security Analysis of the OpenID FAPI 2.0 Family of Protocols: Accompanying a Standardization Process",
    "P. Hosseyni; R. Küsters; T. Würtele", "ACM TOPS 28(1) (full version IACR ePrint 2024/1540)", 2024,
    "https://doi.org/10.1145/3699716", "FT", "include",
    "Seed; full text (ePrint 2024/1540, 186pp, via Wayback copy) read; same RS model extended to Message Signing/CIBA/DCR",
    match=["10.1145/3699716"], src="seed;crossref:D2",
    venue_year="TOPS'24", layer="protocol (symbolic WIM)", oracle="formal proof",
    binding_involved="DPoP; mTLS; FAPI Message Signing (signed resource requests)", placement_modelled="no (RS atomic process, App. C.12 p71-74); reverse proxy only mentioned as cause of A7 response tampering (p12)",
    primitives="none", targets_versions="FAPI 2.0 SP + Message Signing + CIBA + DCR/DCM",
    threat_model="FAPI 2.0 AM; A5 leak modelled after RS response (Sec. 3.3 p14-15; p27 Def.3)", artefact="paper only",
    closest_rq="RQ-L2", kill_risk="low",
    notes="Found DPoP proof replay (Sec 3.3); fix = RS nonces strict one-time use. Our A_leak must account for 'leak after processing'.")
rec("hosseyni2022tr", "Formal Security Analysis of the OpenID Financial-grade API 2.0 (Technical Report WP 1(b))",
    "P. Hosseyni; R. Küsters; T. Würtele", "OpenID Foundation / Univ. Stuttgart technical report", 2022,
    "https://openid.net/wordpress-content/uploads/2022/12/Formal-Security-Analysis-of-FAPI-2.0_FINAL_2022-10.pdf", "FT", "include",
    "Snowball from OIDF announcement page; full text read (Alg. 12 p25, Sec III p4-6)", src="snowball:openid.net",
    venue_year="OIDF TR'22", layer="protocol (symbolic WIM)", oracle="formal proof", binding_involved="DPoP; mTLS",
    placement_modelled="no", primitives="none", targets_versions="FAPI 2.0 Baseline commit 209f58a",
    threat_model="FAPI 2.0 AM draft (A7 = resource request leak)", artefact="report", closest_rq="RQ-L2", kill_risk="low",
    notes="Earliest version of the RS algorithm; identical htu construction.")
rec("fett2019fapi", "An Extensive Formal Security Analysis of the OpenID Financial-Grade API", "D. Fett; P. Hosseyni; R. Küsters",
    "IEEE S&P 2019", 2019, "https://doi.org/10.1109/SP.2019.00067", "MD", "background",
    "Seed lineage (FAPI 1.0); DOI verified via Crossref; no DPoP", match=["1901.11520", "10.1109/SP.2019.00067"], src="arxiv:D2;crossref")
rec("fett2016oauth", "A Comprehensive Formal Security Analysis of OAuth 2.0", "D. Fett; R. Küsters; G. Schmitz", "ACM CCS 2016", 2016,
    "https://doi.org/10.1145/2976749.2978385", "MD", "background", "WIM lineage; DOI verified via Crossref", src="prior review;crossref")
rec("fapiam2025", "FAPI 2.0 Attacker Model (Final)", "D. Fett", "OpenID Foundation specification", 2025,
    "https://openid.net/specs/fapi-attacker-model-2_0-final.html", "SPEC", "include",
    "Priority kill-read: A5 'read resource requests' after processing (Sec 7.7); no intermediaries; internal architecture out of scope (Sec 8.4)", src="seed",
    venue_year="OIDF Final Feb-2025", layer="threat model spec", oracle="n/a", binding_involved="sender-constraining (DPoP/mTLS) assumed",
    placement_modelled="no ('TLS intercepting proxy logs' only as leak source, Sec 7.7)", primitives="n/a", targets_versions="Final 2025-02-22",
    threat_model="A1,A1a,A2,A3a,A4(informative),A5", artefact="spec", closest_rq="RQ-L2/RQ-L4", kill_risk="none",
    notes="Security goal 5.2 phrased as access to resources; A_leak in our paper must be justified relative to A5 post-processing leak.")
rec("fapisp2025", "FAPI 2.0 Security Profile (Final)", "OpenID Foundation FAPI WG", "OpenID Foundation specification", 2025,
    "https://openid.net/specs/fapi-security-profile-2_0-final.html", "MD", "background", "Normative RS requirements; landing page HTTP 200 verified; RS-check text not re-read in this session", src="snowball")

# ---- HTTP differential testing (RQ-L1/RQ-L3) --------------------------------
rec("jabiyev2021treqs", "T-Reqs: HTTP Request Smuggling with Differential Fuzzing", "B. Jabiyev; S. Sprecher; K. Onarlioglu; E. Kirda",
    "ACM CCS 2021", 2021, "https://doi.org/10.1145/3460120.3485384", "MD", "include", "Seed; metadata verified via Crossref (pp.1805-1820)",
    match=["10.1145/3460120.3485384", "T-Reqs: HTTP Request Smuggling"], src="seed;crossref:B1;s2:B1",
    venue_year="CCS'21", layer="HTTP/1.1 proxy<->server parsing", oracle="parsing discrepancy (body/framing boundary)",
    binding_involved="no", placement_modelled="proxy+backend chains (no authz verifier)", primitives="request-line/header/framing mutations",
    targets_versions="popular proxies & servers (2021)", threat_model="remote client crafting raw requests", artefact="UNVERIFIED (not checked this session)",
    closest_rq="RQ-L3", kill_risk="low", notes="Primitive source for G2 framing/method mutations.")
rec("jabiyev2024gudifu", "Gudifu: Guided Differential Fuzzing for HTTP Request Parsing Discrepancies", "B. Jabiyev; A. Gavazzi; K. Onarlioglu; E. Kirda",
    "RAID 2024", 2024, "https://doi.org/10.1145/3678890.3678904", "FT", "include",
    "Seed; NSF-PAR full text skimmed: graybox discrepancy oracle; artefact https://github.com/bahruzjabiyev/gudifu-fuzzer (HTTP 200)",
    match=["10.1145/3678890.3678904", "Gudifu"], src="seed;crossref:B1,B2;s2:B1",
    venue_year="RAID'24", layer="HTTP/1.1 proxies", oracle="parsing discrepancy across whole request (graybox)", binding_involved="no",
    placement_modelled="proxy chains", primitives="whole-request mutations incl. request line, headers", targets_versions="proxies (2024)",
    threat_model="remote client", artefact="public: github.com/bahruzjabiyev/gudifu-fuzzer", closest_rq="RQ-L3", kill_risk="low",
    notes="No token/authorization terms in full text.")
rec("mu2025hdhunter", "The Silent Danger in HTTP: Identifying HTTP Desync Vulnerabilities with Gray-box Testing", "K. Mu; J. Chen; J. Zhuge; Q. Li; H. Duan; N. Feamster",
    "USENIX Security 2025", 2025, "https://www.usenix.org/conference/usenixsecurity25/presentation/mu", "MD", "include",
    "Seed; USENIX page (200) + Zenodo artefact record 14557763 seen in search (zenodo returned 403 to curl); author list from prior review [V-meta]",
    match=["The Silent Danger in HTTP"], src="seed;websearch;s2:B1",
    venue_year="USENIX Sec'25", layer="HTTP requests/responses/CGI", oracle="desync discrepancy (coverage-guided differential)", binding_involved="no",
    placement_modelled="proxy/server chains", primitives="request/response/CGI framing", targets_versions="19 HTTP implementations",
    threat_model="remote client", artefact="public (Zenodo 14557763, HDHunter-1.0.0.zip)", closest_rq="RQ-L3", kill_risk="low",
    notes="Full text not read this session.")
rec("kallus2024garden", "The HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1 Implementations by Differential Fuzzing of Request Streams",
    "B. Kallus; P. Anantharaman; M. E. Locasto; S. W. Smith", "arXiv 2405.17737", 2024, "https://arxiv.org/abs/2405.17737", "FT", "include",
    "Full text skimmed; origin interpretations + gateway transformations; artefact github.com/narfindustries/http-garden (200)",
    match=["2405.17737"], src="arxiv:B2,B4;s2:B1",
    venue_year="arXiv'24", layer="HTTP/1.1 origin+gateway", oracle="parse-tree discrepancy", binding_involved="no", placement_modelled="gateway transformations",
    primitives="request-stream mutations", targets_versions="many servers/proxies", threat_model="remote client",
    artefact="public: github.com/narfindustries/http-garden", closest_rq="RQ-L3", kill_risk="low", notes="Peer-reviewed venue not found.")
rec("jabiyev2022frameshifter", "FRAMESHIFTER: Security Implications of HTTP/2-to-HTTP/1 Conversion Anomalies",
    "B. Jabiyev; S. Sprecher; A. Gavazzi; T. Innocenti; K. Onarlioglu; E. Kirda", "USENIX Security 2022", 2022,
    "https://www.usenix.org/conference/usenixsecurity22/presentation/jabiyev", "MD", "background", "USENIX page title verified (200); H2->H1 primitive source",
    match=["FRAMESHIFTER"], src="prior review;s2:B1")
rec("gavazzi2025h2fuzz", "H2Fuzz: Guided, Black-box, Differential Fuzzing for HTTP/2-to-HTTP/1 Conversion Anomalies", "A. Gavazzi; W. Kong; E. Kirda",
    "RAID 2025", 2025, "https://doi.org/10.1109/RAID67961.2025.00059", "TA", "background", "New 2025 hit (Crossref B1); H2->H1 discrepancy fuzzing; no authz oracle in title/abstract",
    match=["10.1109/raid67961.2025.00059", "H2Fuzz"], src="crossref:B1;s2:B1")
rec("shen2022hdiff", "HDiff: A Semi-automatic Framework for Discovering Semantic Gap Attack in HTTP Implementations",
    "K. Shen; J. Lu; Y. Yang; J. Chen; M. Zhang; H. Duan; J. Zhang; X. Zheng", "IEEE/IFIP DSN 2022", 2022,
    "https://doi.org/10.1109/DSN53405.2022.00014", "MD", "background", "DOI verified via Crossref; spec-derived semantic-gap differential", src="prior review;crossref")
rec("akhavani2025waffled", "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls",
    "S. A. Akhavani; B. Jabiyev; B. Kallus; C. Topcuoglu; S. Bratus; E. Kirda", "ACSAC 2025", 2025, "https://doi.org/10.1109/ACSAC67867.2025.00062", "FT", "include",
    "Priority kill-read; venue ACSAC'25 confirmed by Crossref (pp.689-702); full text arXiv v4 read: oracle = WAF passes + framework executes payload; only 'signature' = WAF signature detection (p3); no tokens",
    match=["2503.10846", "10.1109/acsac67867.2025.00062", "WAFFLED"], src="seed;arxiv:B1,B2;crossref:B2;s2:B1",
    venue_year="ACSAC'25", layer="WAF vs. web framework (body content types)", oracle="WAF verdict allow + framework parses malicious payload",
    binding_involved="no (no token/signature-binding content)", placement_modelled="check layer (WAF) in front of execute layer (framework)",
    primitives="multipart boundary, XML namespace/DOCTYPE, JSON structure, content-type interchange", targets_versions="AWS, Azure, Cloud Armor, Cloudflare, ModSecurity x Flask, Laravel, FastAPI, Gin, Express, Spring Boot",
    threat_model="remote attacker with malicious payload", artefact="public: github.com/sa-akhavani/waffled (bypass requests restricted)",
    closest_rq="RQ-L1", kill_risk="medium (same check-vs-execute structure)", notes="1207 bypasses; HTTP-Normalizer defence. Differentiation: our oracle is cryptographic-binding acceptance + executed op_id; G1/G3 involve no parsing bug.")
rec("topcuoglu2025sync", "HTTP Request Synchronization Defeats Discrepancy Attacks", "C. Topcuoglu; K. Onarlioglu; S. Sprecher; E. Kirda",
    "arXiv 2510.09952", 2025, "https://arxiv.org/abs/2510.09952", "FT", "include",
    "Priority kill-read; full text read: synchronises full URL, Host, framing (p1); message signatures dismissed (p5); method/override headers/body semantics not synchronised; artefact URL (p15) -> GitHub account with 0 public repos on 2026-11-23",
    match=["2510.09952"], src="seed;arxiv:B1",
    venue_year="arXiv'25", layer="proxy chain (Apache, NGINX, HAProxy, Varnish, Cloudflare)", oracle="n/a (defence); consistency of per-hop processing history",
    binding_involved="no (does not bind to client proof)", placement_modelled="multi-hop proxies; origin optional",
    primitives="path confusion, host confusion, framing confusion", targets_versions="5 proxy technologies", threat_model="attacker controls request; servers honest; TLS",
    artefact="NOT public: github.com/http-request-sync/defeats_discrepancy_attacks 404; user has 0 repos (checked 2026-11-23)",
    closest_rq="RQ-L3", kill_risk="medium (as baseline defence for G2)", notes="Cannot cover G1 (method override header, query/body dispatch) or G3; must be evaluated/argued as baseline.")
rec("chen2016host", "Host of Troubles: Multiple Host Ambiguities in HTTP Implementations", "J. Chen; J. Jiang; H. Duan; N. Weaver; T. Wan; V. Paxson",
    "ACM CCS 2016", 2016, "https://doi.org/10.1145/2976749.2978394", "MD", "include", "DOI verified via Crossref; check-layer bypass via Host ambiguity",
    src="prior review;websearch;crossref",
    venue_year="CCS'16", layer="HTTP Host semantics across proxies/firewalls/CDNs", oracle="divergent Host interpretation -> cache poisoning / filter bypass",
    binding_involved="no", placement_modelled="middlebox + server", primitives="duplicate Host, absolute-URI vs Host, space/tab variants", targets_versions="2016 implementations",
    threat_model="remote client", artefact="UNVERIFIED", closest_rq="RQ-L3", kill_risk="low", notes="Source for Host vs :authority primitives.")
rec("mirheidari2020cached", "Cached and Confused: Web Cache Deception in the Wild", "S. A. Mirheidari; S. Arshad; K. Onarlioglu; B. Crispo; E. Kirda; W. Robertson",
    "USENIX Security 2020", 2020, "https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari", "MD", "include", "USENIX page title verified (200)",
    match=["1912.10190"], src="arxiv:B3;prior review",
    venue_year="USENIX Sec'20", layer="cache vs origin path interpretation", oracle="cache stores private response (path confusion)", binding_involved="no",
    placement_modelled="CDN/cache + origin", primitives="path parameters, encoded delimiters", targets_versions="Alexa top sites (2019)", threat_model="web attacker + victim click",
    artefact="UNVERIFIED", closest_rq="RQ-L3", kill_risk="low", notes="Path-confusion primitives (%2F, ;, %3F).")
rec("nguyen2019cpdos", "Your Cache Has Fallen: Cache-Poisoned Denial-of-Service Attack", "H. V. Nguyen; L. Lo Iacono; H. Federrath", "ACM CCS 2019", 2019,
    "https://doi.org/10.1145/3319535.3354215", "MD", "background", "DOI verified via Crossref; includes HTTP method override header as CPDoS vector (per prior review; not re-read)", src="prior review;crossref")
rec("buttner2021whitelist", "Less is Often More: Header Whitelisting as Semantic Gap Mitigation in HTTP-Based Software Systems",
    "A. Büttner; H. V. Nguyen; N. Gruschka; L. Lo Iacono", "IFIP SEC 2021 (IFIP AICT 625)", 2021, "https://doi.org/10.1007/978-3-030-78120-0_22", "MD", "background",
    "DOI verified via Crossref; defence baseline for header-based gaps (G3)", src="prior review;crossref")
rec("reynolds2022equivocal", "Equivocal URLs: Understanding the Fragmented Space of URL Parser Implementations", "J. Reynolds; A. Bates; M. Bailey",
    "ESORICS 2022", 2022, "https://doi.org/10.1007/978-3-031-17143-7_9", "MD", "background", "DOI verified via Crossref; URL-parser differentials (G2 htu canonicalisation)", src="prior review;crossref")
rec("nygren2025binding", "HTTP/1.1 Request Smuggling Defense using Cryptographic Message Binding (draft-nygren-httpbis-http11-request-binding)",
    "E. Nygren; M. Bishop", "IETF Internet-Draft (individual)", 2025, "https://datatracker.ietf.org/doc/draft-nygren-httpbis-http11-request-binding/", "MD", "background",
    "Datatracker page HTTP 200; content not read this session (versions/dates per prior review UNVERIFIED)", src="seed list;prior review")

# ---- Check-vs-execute / method semantics (RQ-L1, RQ-L4) ----------------------
rec("golinelli2026post", "When POST Becomes GET: Investigating HTTP Method Interchangeability and Its Security Implications",
    "M. Golinelli; S. E. Hannachi; B. Crispo", "arXiv 2610.37474", 2026, "https://arxiv.org/abs/2610.37474", "FT", "include",
    "NEW close hit (arXiv C3 query); full text read: method interchangeability POST->GET, oracle = response equivalence vs no-query baseline; CSRF token check method-scoped; frameworks App. A; method-override headers only cited (p4)",
    match=["2610.37474"], src="arxiv:C3",
    venue_year="arXiv Oct-2026", layer="web application/framework routing", oracle="response equivalence (GET-converted vs POST) + CSRF-token acceptance per method",
    binding_involved="no (CSRF tokens, not PoP)", placement_modelled="no (single app; mentions nginx proxy_method p2)", primitives="POST->GET conversion, body->query parameter move",
    targets_versions="Tranco top-10k (407 sites 4.1%); frameworks: PHP, Spring MVC, ASP.NET Core, Laravel, Flask, Rails, Sinatra, Gin, Django, Express, FastAPI, NestJS, Next.js, SvelteKit",
    threat_model="web attacker (CSRF, WCD)", artefact="public: github.com/Golim/method-interchange", closest_rq="RQ-L1/RQ-L4",
    kill_risk="medium for G1 method (prior art on method-scoped defence gaps); low for core claim",
    notes="Must cite in G1 and in E2 (framework survey). Differentiation: htm-bound proof accepted for M, executor runs M' via override; we test override middleware & dispatch-by-query/body across gateway placements.")
rec("mancinas2026", "Operational Realities of Sender-Constrained OAuth: Replay-State Scaling Thresholds and Silent Binding Failures in Distributed Resource-Server Deployments",
    "S. E. Mancinas Fontalvo", "Preprint (author website; no venue found)", 2026, "https://sergioemancinas.com/papers/mancinas-sender-constrained-oauth-2026.pdf", "FT", "include",
    "NEW close hit (web search); full 11pp read: B1 bounded jti cache replay threshold (Spring Security 6.5, ~17 req/s), B2 TLS-termination/XFCC propagation (mTLS), B3 AS audience bypass; no request->operation oracle; htu only in background",
    src="websearch",
    venue_year="preprint Jul-2026", layer="RS deployment (Spring Security, Keycloak, NGINX/Envoy mTLS termination)", oracle="replay admitted (jti cache eviction); 401 vs accept for XFCC loss",
    binding_involved="DPoP (jti/iat), mTLS (cnf.x5t#S256)", placement_modelled="partly (TLS-terminating intermediary for mTLS, Sec VI-B p7)",
    primitives="cache flooding; XFCC absent/percent-encoded", targets_versions="Spring Security 6.5.x, Keycloak 26.6.1, Envoy",
    threat_model="leaked proof replay; LAN attacker for XFCC", artefact="public: github.com/sergioemancinas/dpop-replay-threshold",
    closest_rq="RQ-L1/RQ-L4", kill_risk="low-medium (coins 'silent binding failures'; overlaps G3 conceptually)",
    notes="Says DPoP unaffected by TLS-termination class because binding is app-layer (p7) - our G1/G2 show app-layer binding is still view-relative. Single-author, not peer-reviewed.")
rec("kodathala2026effect", "Approve What, Exactly? Effect Binding and Trusted Rendering for Agent Step-Up Authorization",
    "S. V. Kodathala; P. Pollishetty; J. Cargill", "arXiv 2610.21063", 2026, "https://arxiv.org/abs/2610.21063", "TA", "background",
    "Abstract: approvals must name exactly what they approve (effect binding) - conceptual analogue for agent payments; no HTTP/DPoP (grep of full text: no DPoP/htu)", match=["2610.21063"], src="arxiv:D4")

# ---- Sender-constraint testing / measurement (RQ-L4) ------------------------
rec("yang2026jwteemo", "Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery",
    "J. Yang; E. Wang; J. Chen; Q. Wang; Y. Zhang; H. Duan; W. Xie; B. Wang", "NDSS 2026", 2026,
    "https://www.ndss-symposium.org/ndss-paper/token-time-bomb-evaluating-jwt-implementations-for-vulnerability-discovery/", "FT", "include",
    "Seed; full text (NDSS PDF) read: 0 occurrences of DPoP/htu/cnf/sender-constrained; artefact github.com/JWTeemo/JWTeemo (200)", src="seed;websearch",
    venue_year="NDSS'26", layer="JWT/JOSE libraries", oracle="parsing discrepancy across libraries + resource exhaustion", binding_involved="no (JWS/JWE level only)",
    placement_modelled="no", primitives="format/alg/sign-encrypt confusion, billion hashes, compression DoS", targets_versions="43 libraries, 10 languages",
    threat_model="token forger / DoS", artefact="public: github.com/JWTeemo/JWTeemo", closest_rq="RQ-L4", kill_risk="low (no DPoP) but group could follow up",
    notes="20 CVEs; IETF engagement.")
rec("philippaerts2022oauch", "OAuch: Exploring Security Compliance in the OAuth 2.0 Ecosystem", "P. Philippaerts; D. Preuveneers; W. Joosen",
    "RAID 2022", 2022, "https://doi.org/10.1145/3545948.3545955", "MD", "include", "Seed; DOI verified via Crossref; AS-only compliance tester (per authors' slides)", src="seed;websearch;crossref",
    venue_year="RAID'22", layer="OAuth authorization servers", oracle="spec-compliance test verdicts", binding_involved="no RS-side binding",
    placement_modelled="no", primitives="113 test cases from 10 documents (slides)", targets_versions="100 deployed IdPs", threat_model="OAuth threat model/BCP",
    artefact="public tool (oauch.io; github.com/DistriNet/OAuch per prior review)", closest_rq="RQ-L4", kill_risk="low", notes="Methodology precedent for compliance measurement.")
rec("zhou2026mcp", "A First Measurement Study on Authentication Security in Real-World Remote MCP Servers", "H. Zhou; X. Zhang; H. Zhang; H. Zhang; M. Zhang; M. Yang",
    "arXiv 2605.22333", 2026, "https://arxiv.org/abs/2605.22333", "FT", "include", "Full text grep: 0 DPoP/htu/sender-constrained occurrences; MCP server as OAuth RS", match=["2605.22333"], src="arxiv:D4",
    venue_year="arXiv May-2026", layer="MCP servers (OAuth RS)", oracle="authentication weakness checks", binding_involved="no", placement_modelled="no",
    primitives="n/a", targets_versions="real-world remote MCP servers", threat_model="remote client", artefact="UNVERIFIED", closest_rq="RQ-L4", kill_risk="low", notes="Closest RS-side measurement; no PoP.")
rec("padilla2026mcp", "Exposed by Design: A Dynamic Security Assessment of Internet-Facing MCP Servers at Scale", "N. Padilla",
    "arXiv 2608.00150", 2026, "https://arxiv.org/abs/2608.00150", "FT", "background", "Full text grep: no DPoP; single-author; tool github.com/CobaltoSec/corvus", match=["2608.00150"], src="arxiv:D4")
rec("zhang2026miniprog", "Mini-Programs, Mega-Problems: Unveiling OAuth-based Authentication Misuses in Mini-Programs via Dynamic Analysis",
    "Z. Zhang; Z. Xie; L. Ying; et al.", "arXiv 2607.08232 (stated CCS'26 per prior review, UNVERIFIED)", 2026, "https://arxiv.org/abs/2607.08232", "FT", "exclude",
    "E5: client/AS-side OAuth misuse; full-text grep: no DPoP/htu", src="prior review")
rec("villa2026chai", "Chai: Agentic Discovery of Cryptographic Misuse Vulnerabilities", "C. Villa; S. Kim; A. Chu; A. Shakevsky; R. A. Popa",
    "arXiv 2606.26933", 2026, "https://arxiv.org/abs/2606.26933", "FT", "exclude", "E5: crypto misuse generally; full-text grep: no DPoP/htu", src="prior review")

# ---- Conceptual authority/binding (RQ-L1 framing) ----------------------------
rec("gallo2026continuity", "Proof-of-Continuity: A Temporal Model for Authority Propagation in Distributed Systems and AI Agents", "N. Gallo",
    "arXiv 2607.08906", 2026, "https://arxiv.org/abs/2607.08906", "FT", "include",
    "Priority kill-read; full text: conceptual PIC model; DPoP binds to key/channel not causal chain (Sec 4.1 p5; p19); no evaluation, no HTTP experiments",
    match=["2607.08906"], src="seed;arxiv:A2,AxB",
    venue_year="arXiv Jul-2026", layer="abstract authority propagation (multi-hop)", oracle="none (formal argument)", binding_involved="discusses DPoP/Token Binding conceptually",
    placement_modelled="multi-hop chains abstractly", primitives="none", targets_versions="none", threat_model="confused deputy", artefact="none",
    closest_rq="RQ-L1", kill_risk="low", notes="Cite as conceptual motivation; we measure concrete HTTP stacks.")
rec("gallo2026relational", "Beyond Proof of Possession: A Relational Theory of Authority", "N. Gallo", "arXiv 2611.07159", 2026,
    "https://arxiv.org/abs/2611.07159", "FT", "background", "NEW (arXiv A2); full-text grep: DPoP 'binds each proof to HTTP request properties'; conceptual follow-up of 2607.08906; no measurement",
    match=["2611.07159"], src="arxiv:A2;websearch")
rec("kim2026tbsg", "Trust Boundary Semantic Gaps: A Multi-dimensional Analysis and Mitigation for Security-by-Design", "D. Kim; J.-Y. Choi; J. Lee",
    "arXiv 2607.01711", 2026, "https://arxiv.org/abs/2607.01711", "FT", "include",
    "Priority kill-read; full text: design-time taxonomy (Identity/Spatial/Temporal/Interpretation) from 75 incidents; SolarWinds case; no HTTP measurement",
    match=["2607.01711"], src="seed",
    venue_year="arXiv Jul-2026", layer="generic trust boundaries", oracle="none (retrospective analysis)", binding_involved="signatures/tokens accepted yet insufficient (abstract)",
    placement_modelled="boundary-level", primitives="none", targets_versions="75 incidents 2014-2025", threat_model="generic", artefact="none",
    closest_rq="RQ-L1", kill_risk="low", notes="'Interpretation' dimension subsumes parser differentials (p6). Cite and differentiate.")
rec("iammongkol2026parse", "Access Control as Verified Parse Constraints", "S. Iammongkol; Z. Huang; D. Eyers", "arXiv 2609.12488", 2026,
    "https://arxiv.org/abs/2609.12488", "TA", "background", "Abstract: verified gateway parser (EverParse); one-sided, no backend comparison", match=["2609.12488"], src="arxiv:BxCxD")
rec("nguyen2020crehma", "CREHMA: Cache-aware REST-ful HTTP Message Authentication", "H. V. Nguyen; L. Lo Iacono", "ACM CODASPY 2020", 2020,
    "https://doi.org/10.1145/3374664.3375750", "TA", "background", "NEW (Crossref D1): end-to-end HTTP message signatures through caches; signature-coverage precedent", match=["10.1145/3374664.3375750"], src="crossref:D1")
rec("somorovsky2012saml", "On Breaking SAML: Be Whoever You Want to Be", "J. Somorovsky; A. Mayer; J. Schwenk; M. Kampmann; M. Jensen", "USENIX Security 2012", 2012,
    "https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky", "MD", "background",
    "USENIX page title verified; XSW = verified element != processed element ('sign what you execute' precedent)", src="prior review")

# ---- Standards / WG / advisories (RQ-L4) -----------------------------------
rec("rfc9449", "OAuth 2.0 Demonstrating Proof of Possession (DPoP) (RFC 9449)", "D. Fett; B. Campbell; J. Bradley; T. Lodderstedt; M. Jones; D. Waite",
    "IETF RFC", 2023, "https://doi.org/10.17487/RFC9449", "SPEC", "background", "Core standard; Crossref metadata verified", match=["10.17487/rfc9449"], src="crossref:A1")
rec("rfc8705", "OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (RFC 8705)", "B. Campbell; J. Bradley; N. Sakimura; T. Lodderstedt",
    "IETF RFC", 2020, "https://doi.org/10.17487/RFC8705", "SPEC", "background", "Crossref verified", match=["10.17487/rfc8705"], src="crossref:A4;s2:A4")
rec("rfc9421", "HTTP Message Signatures (RFC 9421)", "A. Backman; J. Richer; M. Sporny", "IETF RFC", 2024, "https://www.rfc-editor.org/rfc/rfc9421",
    "SPEC", "background", "Authors from RFC text header (Crossref lists only Sporny)", match=["10.17487/rfc9421"], src="crossref:D1")
rec("rfc9440", "Client-Cert HTTP Header Field (RFC 9440)", "B. Campbell; M. Bishop", "IETF RFC", 2023, "https://doi.org/10.17487/RFC9440", "SPEC", "background", "Crossref verified; G3 propagation header", src="prior review;crossref")
rec("rfc9700", "Best Current Practice for OAuth 2.0 Security (RFC 9700)", "T. Lodderstedt; J. Bradley; A. Labunets; D. Fett", "IETF RFC (BCP 240)", 2025,
    "https://doi.org/10.17487/RFC9700", "SPEC", "background", "Crossref verified", src="prior review;crossref")
rec("allam2026thread", "[OAUTH-WG] rfc9449 (proposal: Making htm and htu Optional to Enable Wider Adoption)", "B. Allam", "oauth@ietf.org mailing list", 2026,
    "https://www.mail-archive.com/oauth@ietf.org/msg26175.html", "SPEC", "include",
    "Priority kill-read; message read; thread index (thrd2) and IETF archive search show no replies as of 2026-11-23", src="seed",
    venue_year="IETF OAuth WG list 29-Jun-2026", layer="standards", oracle="n/a", binding_involved="DPoP htm/htu", placement_modelled="argues proxies rewrite URIs",
    primitives="URI-rewriting proxies", targets_versions="RFC 9449 s4.2", threat_model="argues TLS+aud/scope/ath/jti suffice", artefact="attached draft proposal",
    closest_rq="RQ-L4", kill_risk="none (motivation)", notes="Proposes AS metadata dpop_request_binding_required + two profiles. No WG outcome found.")
rec("madden2025thread", "[OAUTH-WG] DPoP tokens vs downstream resource servers (Y. Zehavi; reply N. Madden)", "Y. Zehavi; N. Madden", "oauth@ietf.org mailing list", 2025,
    "https://go.mail-archive.com/oauth@ietf.org/msg24959.html", "SPEC", "include",
    "Resume pass 2026-11-23: msg24959 (Madden, 16-Oct-2025) and msg24995 (Zehavi, 18-Oct-2025) read; forwarding DPoP to downstream RS breaks htu; Madden: backend trust in token 'fails to guarantee that the token relates to the backend API requests being made'", src="websearch",
    venue_year="IETF OAuth WG list Oct-2025", layer="standards (gateway -> downstream RS)", oracle="n/a", binding_involved="DPoP htu",
    placement_modelled="yes, informally (edge gateway vs downstream RS; phantom-token pattern)", primitives="token forwarding; htu mismatch downstream",
    targets_versions="RFC 9449", threat_model="informal", artefact="none", closest_rq="RQ-L4", kill_risk="none (motivation; practitioner statement of the gap, no measurement)",
    notes="Supports G3/placement framing: WG experts acknowledge backends trust gateway; proposals relax htu downstream. Only 2 messages read, thread outcome not traced.")
rec("sep1932", "SEP-1932: DPoP Profile for MCP", "P. Kasselman (GitHub: PieterKas)", "Model Context Protocol SEP (GitHub PR #1932, open)", 2025,
    "https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1932", "SPEC", "include",
    "Priority kill-read: open draft; defers to RFC 9449 s4.3; jti tracking NOT required; no mention of proxies/gateways/normalisation", src="seed",
    venue_year="MCP SEP Dec-2025 (open)", layer="standards (MCP)", oracle="n/a", binding_involved="DPoP", placement_modelled="no", primitives="n/a",
    targets_versions="ext-auth draft dpop-extension.mdx", threat_model="token theft", artefact="spec draft", closest_rq="RQ-L4", kill_risk="none (motivation)",
    notes="Author real name inferred from handle: UNVERIFIED; use handle in bib.")
rec("mcpconf369", "Server Auth: DPoP Proof Validation (SEP-1932) (modelcontextprotocol/conformance issue #369)", "PieterKas (GitHub)", "GitHub issue (open; PR #395)", 2026,
    "https://github.com/modelcontextprotocol/conformance/issues/369", "SPEC", "include",
    "Priority kill-read: RS negative tests incl. htm, htu (ignoring query/fragment), ath, iat, missing claims, Bearer downgrade, cnf.jkt; no proxies", src="seed",
    venue_year="GitHub Jun-2026", layer="conformance tests (MCP RS)", oracle="per-check reject expected", binding_involved="DPoP", placement_modelled="no (single endpoint)",
    primitives="claim mutations", targets_versions="conformance PR #395", threat_model="n/a", artefact="test suite (in progress)", closest_rq="RQ-L4", kill_risk="low",
    notes="Tests a single RS endpoint; does not test proof minted for op A replayed as op B.")
rec("grpcgw2026cve37236", "CVE-2026-37236: grpc-gateway X-HTTP-Method-Override rewrites method before routing, bypassing upstream method-based controls", "grpc-gateway maintainers / NVD",
    "Security advisory", 2026, "https://osv.dev/vulnerability/CVE-2026-37236", "MD", "include",
    "Resume pass 2026-11-23: OSV API record read (published 2026-08-28; fix commit 72123cd); 'allows bypassing method-based access controls enforced by upstream proxies or WAFs'", src="websearch",
    venue_year="advisory 2026", layer="upstream proxy/WAF -> grpc-gateway router", oracle="method-ACL bypass", binding_involved="no (method ACL)",
    placement_modelled="edge check, backend override", primitives="X-HTTP-Method-Override on POST form-urlencoded", targets_versions="grpc-gateway <= v2.28.0 (fixed at commit 72123cd)",
    threat_model="remote client", artefact="advisory + fix commit", closest_rq="RQ-L3/RQ-L4", kill_risk="none (product bug; direct G1 htm evidence)",
    notes="An htm-bound DPoP check at the edge is exactly such an upstream method-based control.")
rec("croft2026devlog", "wolfram closes a DPoP sender-constraint bypass and hardens identity resolution (project devlog)", "unknown (project blog)",
    "Blog post", 2026, "https://devlog.croft.click/2026/08/12/wolfram-protocol-correctness", "TA", "exclude",
    "E3: project changelog (search snippet only); unbound token rebound to proof key; no placement/differential/method aspect", src="websearch")
rec("traefik2026cve40912", "CVE-2026-40912: Traefik StripPrefixRegex + ForwardAuth dot-segment authorization bypass (GHSA-6jwx-7vp4-9847)", "Traefik maintainers / NVD",
    "Security advisory", 2026, "https://nvd.nist.gov/vuln/detail/CVE-2026-40912", "MD", "include",
    "NVD page 200; details from secondary sources in search: ForwardAuth sees dot-segment X-Forwarded-Uri that does not match protected patterns", src="prior review;websearch",
    venue_year="advisory 2026", layer="gateway (Traefik) -> ForwardAuth -> backend", oracle="path-ACL bypass", binding_involved="no (path ACL)", placement_modelled="edge forward-auth",
    primitives="dot-segments + StripPrefixRegex RawPath desync", targets_versions="Traefik <2.11.43, <3.6.14", threat_model="remote client", artefact="advisory",
    closest_rq="RQ-L1/RQ-L3", kill_risk="none (product bug; supports G2)", notes="Evidence that edge verifier view != executor view in ForwardAuth placement.")
rec("istio2021cve31920", "CVE-2021-31920 / ISTIO-SECURITY-2021-005: authorization policy bypass via multiple or escaped slashes", "Istio / NVD",
    "Security advisory", 2021, "https://istio.io/latest/news/security/istio-security-2021-005/", "MD", "include",
    "Istio bulletin page 200; //admin bypasses DENY /admin; relates to Envoy CVE-2021-29492", src="prior review;websearch",
    venue_year="advisory 2021", layer="mesh (Envoy RBAC/AuthorizationPolicy) -> backend", oracle="path-ACL bypass", binding_involved="no", placement_modelled="sidecar/edge",
    primitives="//, %2F, %5C", targets_versions="Istio <1.8.6, <1.9.5", threat_model="remote client", artefact="advisory", closest_rq="RQ-L3", kill_risk="none", notes="G2 primitive provenance.")
rec("opaenvoy2026cve26205", "CVE-2026-26205: opa-envoy-plugin input.parsed_path double-slash misinterpretation (GHSA-9f29-v6mm-pw6w)", "OPA maintainers / NVD",
    "Security advisory", 2026, "https://nvd.nist.gov/vuln/detail/CVE-2026-26205", "MD", "include", "NVD page 200; PDP evaluates different path than served", src="prior review;websearch",
    venue_year="advisory 2026", layer="Envoy ext_authz PDP (OPA)", oracle="path-ACL bypass", binding_involved="no", placement_modelled="ext_authz",
    primitives="leading //", targets_versions="<1.13.2-envoy-2", threat_model="remote client", artefact="advisory", closest_rq="RQ-L3", kill_risk="none", notes="ext_authz placement evidence.")
rec("envoy2019ghsa", "Envoy GHSA-xcx5-93pw-jw2w: unnormalised paths seen by routing and all L7 filters including ext_authz", "Envoy maintainers", "Security advisory", 2019,
    "https://github.com/envoyproxy/envoy/security/advisories/GHSA-xcx5-93pw-jw2w", "MD", "include", "Advisory page 200; 'unnormalized view of the path is used for routing and all L7 filter execution, including RBAC, ext_authz'",
    src="prior review;websearch",
    venue_year="advisory (Envoy <=1.9)", layer="Envoy", oracle="path-ACL bypass", binding_involved="no", placement_modelled="ext_authz", primitives="dot-segments",
    targets_versions="Envoy <=1.9", threat_model="remote client", artefact="advisory", closest_rq="RQ-L3", kill_risk="none", notes="Year per advisory context; exact publication date UNVERIFIED.")

# ---- Screened and excluded (title/abstract) with specific reasons ------------
EX = [
 ("Request Smuggling Via HTTP/2 Cleartext in the Wild: Empirical Testing with Differential Fuzzing", "10.1109/itiotsc60379.2023.00043", "E6: smuggling measurement, no authorization/proof oracle; primitives covered by T-Reqs/HDHunter"),
 ("Attacking Websites Using HTTP Request Smuggling: Empirical Testing of Servers and Proxies", "10.1109/edoc52215.2021.00028", "E6: smuggling primitives covered by included works"),
 ("HTTP/3 will not Save you from Request Smuggling", "10.1109/nca61908.2024.00026", "E6: H3 header validation; no authz oracle"),
 ("Email Smuggling with Differential Fuzzing of MIME Parsers", "10.1109/spw67851.2025.00007", "E1: email/MIME domain"),
 ("SmuggleDoS: Evasive DDoS Attacks using HTTP Request Smuggling", "10.1109/etaact69135.2026.11541337", "E5: DDoS goal, no binding/authz"),
 ("A Methodology for Web Cache Deception Vulnerability Discovery", "10.5220/0012692000003711", "E6: WCD methodology; covered by Cached and Confused"),
 ("Mutual TLS in Practice: A Deep Dive into Certificate Configurations and Privacy Issues", "10.1145/3646547.3688415", "E5: mTLS certificate ecosystem; not token binding to requests"),
 ("A Study of OAuth 2.0 Risk Notification and Token Revocation from Resource Server", "10.1007/978-3-319-31875-2_23", "E5: revocation, not binding"),
 ("Implementing Secure API Gateways: A Case Study of AWS API Gateway and Spring Cloud Gateway", "10.1109/icbiti65527.2025.11500898", "E3: case study/tutorial, no measurement method"),
 ("Research on authorization verification method of API gateway in grid microservice architecture", "10.1117/12.2668095", "E3/E5: design proposal, no differential/binding analysis"),
 ("Security Challenges in API Gateway Design for Cloud-Based Applications", "10.21275/sr23914095135", "E3: survey-style, no method"),
 ("The Authorization Gap: Rethinking API Security Architecture for Autonomous AI Agents", "10.2139/ssrn.7398298", "E3: position (SSRN)"),
 ("Analysis and mitigation of JWT and OAuth 2.0 vulnerabilities in REST APIs", "10.30837/rt.2026.2.225.05", "E3/E5: generic JWT/OAuth overview"),
 ("A Hybrid Approach for Detecting Broken Object Level Authorization (BOLA) Vulnerabilities", "10.51408/csit2025_40", "E5: BOLA logic, not binding"),
 ("Group Signatures for Privacy-Preserving HTTP Message Authentication", "10.1109/urtc68753.2025.11533152", "E5: anonymity of HTTP signatures"),
 ("Nonce-based authenticated key establishment over OAuth 2.0 IoT proof-of-possession architecture", "10.1109/wf-iot.2016.7845424", "E5: IoT PoP key establishment; no layered HTTP"),
 ("Differential regression testing for REST APIs", "", "E5: regression testing (S2 B1 hit)"),
 ("Blind Spots: Identifying Exploitable Program Inputs", "", "E5: ignored inputs generally; tangential (S2 B1 hit)"),
 ("Hard-Earned Lessons in Access Control at Scale: Enforcing Identity and Policy Across Trust Boundaries with Reverse Proxies and mTLS", "2508.01863", "E3: experience report, no differential/binding analysis (arXiv CxD)"),
 ("BACGUARD: Fact-Grounded Runtime Mitigation of Broken Access Control", "2611.10157", "E5: BAC mitigation, no proof binding"),
 ("Proof-Carrying Agent Actions: Model-Agnostic Runtime Governance for Heterogeneous Agent Systems", "2606.04104", "E5: agent action certificates; conceptual analogue only"),
 ("Agentic JWT: A Secure Delegation Protocol for Autonomous AI Agents", "2509.13597", "E5: new token design (intent binding); no layered verification measurement"),
 ("Provable Authority: A Protocol for Verifiable Authority Resolution and Control Across Human, Organizational, and Agentic Transactions", "2610.22899", "E5: authority protocol; not HTTP binding"),
 ("Give Them an Inch and They Will Take a Mile:Understanding and Measuring Caller Identity Confusion in MCP-Based AI Systems", "2603.07473", "E5: MCP caller identity, no PoP binding (abstract)"),
 ("When Tool Names Are Not Identities: Measuring Provider Misbinding in MCP-Based AI Agents", "2611.21577", "E5: tool-provider misbinding (naming), not request binding"),
 ("Auditable Session Admission for Cross-Silo Federated Learning", "2607.16559", "E1/E5: FL session admission"),
 ("SUDP: Secret-Use Delegation Protocol for Agentic Systems", "2604.24920", "E5: delegation protocol"),
 ("ACLE-MCP: Attested Capability Leases for Execution-Time Trust in Remote LLM Tool Use", "2609.02690", "E5: capability leases; no HTTP binding measurement"),
 ("Compromise Is Not Consequence: Evaluating Task-Scoped Authorization in LLM Agents with Paired Replay", "2610.05840", "E5: agent authorization scope"),
 ("NEBULA: A Language - Independent Specification for Opaque Rotating Refresh Tokens", "2608.04115", "E5: refresh tokens"),
 ("Capability-Based Multi-Tenant Access Management in Crowdsourced Drone Services", "2505.01048", "E1"),
 ("A Capability-based Distributed Authorization System to Enforce Context-aware Permission Sequences", "2211.04980", "E5"),
 ("OAuth 2.0 authorization using blockchain-based tokens", "2001.10461", "E5"),
 ("Federated Computing as Code (FCaC): Sovereignty-aware Systems by Design", "2603.17331", "E1"),
 ("Blind Spots: Automatically detecting ignored program inputs", "2301.08700", "E5"),
 ("How Effective Are Neural Networks for Fixing Security Vulnerabilities", "2305.18607", "E1"),
 ("Understanding and Mitigating the Security Risks of Content Inclusion in Web Browsers", "2001.03643", "E5: browser content inclusion"),
 ("Large-Scale Analysis of Style Injection by Relative Path Overwrite", "1811.00917", "E5: client-side RPO"),
 ("Layer Order Semantics for Automata-Based Cybersecurity", "2606.10649", "E5"),
 ("A Security Analysis of the OpenClaw AI Agent Framework", "2603.27517", "E5"),
]

# Generic off-topic reason for remaining API hits
GENERIC = "E1: off-topic by title/abstract (homonym or unrelated domain)"
DOMAIN_KW = ["http", "oauth", "token", "proxy", "gateway", "smuggl", "authoriz", "authentic", "signature", "tls", "jwt", "api", "cache", "certificate"]
E5 = "E5: in-domain keyword but no request-binding, interpretation-differential or verifier-placement analysis (title/abstract)"
def generic(title):
    t = (title or "").lower()
    return E5 if any(k in t for k in DOMAIN_KW) else GENERIC

def norm(s): return re.sub(r"[^a-z0-9]", "", (s or "").lower())

def main():
    rows, ids = [], 0
    def add(title, authors, venue, year, url, stage, decision, reason):
        nonlocal ids
        ids += 1
        rows.append(dict(id=f"S{ids:03d}", title=title, authors=authors, venue=venue, year=year, url=url, stage=stage, decision=decision, reason=reason))
    matched = set()
    for c in C:
        add(c["title"], c["authors"], c["venue"], c["year"], c["url"], c["stage"], c["decision"], c["reason"] + (f" [found via: {c['src']}]" if c["src"] else ""))
        for m in c["match"]: matched.add(norm(m))
        matched.add(norm(c["title"])[:60])
    exmap = {}
    for t, ident, why in EX:
        exmap[norm(ident) if ident else norm(t)[:60]] = (t, why)
    # arXiv hits
    for fn in ("arx_results.json", "arx_results2.json"):
        for q, v in json.load(open(os.path.join(LOG, fn))).items():
            for it in v["items"]:
                aid = it["id"].split("v")[0]
                k = norm(aid)
                if k in matched or norm(it["title"])[:60] in matched: continue
                matched.add(k)
                t, why = exmap.get(k, (it["title"], generic(it["title"])))
                add(it["title"], it["authors"], f"arXiv {aid}", it["published"][:4], f"https://arxiv.org/abs/{aid}", "TA", "exclude", f"{why} [arXiv query {fn.split('.')[0]}:{q}]")
    # Crossref hits: top 15 per query were screened by title
    for q, v in json.load(open(os.path.join(LOG, "cr_results.json"))).items():
        for it in v["items"][:15]:
            doi = it["DOI"]; k = norm(doi); title = (it.get("title") or [""])[0]
            if k in matched or norm(title)[:60] in matched: continue
            matched.add(k)
            au = "; ".join(f"{a.get('given','')} {a.get('family','')}".strip() for a in it.get("author", [])[:6])
            y = it.get("issued", {}).get("date-parts", [[None]])[0][0]
            _, why = exmap.get(k, (title, generic(title)))
            add(title, au, (it.get("container-title") or [""])[0] or it.get("type", ""), y, f"https://doi.org/{doi}", "TA", "exclude", f"{why} [Crossref query {q}]")
    # Semantic Scholar hits (3 queries returned; top 20 screened)
    s2 = json.load(open(os.path.join(LOG, "s2_results.json")))
    for q, v in s2.items():
        for it in (v["items"] or [])[:20]:
            title = it["title"]; k = norm(title)[:60]
            doi = (it.get("externalIds") or {}).get("DOI"); ax = (it.get("externalIds") or {}).get("ArXiv")
            if k in matched or (doi and norm(doi) in matched) or (ax and norm(ax) in matched): continue
            matched.add(k)
            _, why = exmap.get(k, (title, generic(title)))
            au = "; ".join(a["name"] for a in (it.get("authors") or [])[:6])
            add(title, au, it.get("venue") or "", it.get("year"), it.get("url") or "", "TA", "exclude", f"{why} [S2 query {q}]")
    # leftover EX items not hit by any API dump (from web search screening)
    for k, (t, why) in exmap.items():
        if k not in matched:
            add(t, "", "", "", "", "TA", "exclude", why + " [web search]")
    with open(os.path.join(LIT, "screening.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "title", "authors", "venue", "year", "url", "stage", "decision", "reason"])
        w.writeheader(); w.writerows(rows)
    # extraction
    fields = ["id", "venue_year", "layer", "oracle", "binding_involved", "placement_modelled", "primitives", "targets_versions", "threat_model", "artefact", "closest_rq", "kill_risk", "notes"]
    with open(os.path.join(LIT, "extraction.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for c in C:
            if c["decision"] == "include":
                w.writerow({"id": c["key"], **{k: c["ext"].get(k, "") for k in fields[1:]}})
    # related matrix (rows = included papers + key background works compared in related.tex)
    with open(os.path.join(LIT, "related_matrix.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["paper", "oracle", "layer", "binding", "placement", "artefact"])
        for c in C:
            if c["decision"] == "include":
                e = c["ext"]
                w.writerow([c["key"], e.get("oracle", ""), e.get("layer", ""), e.get("binding_involved", ""), e.get("placement_modelled", ""), e.get("artefact", "")])
        w.writerow(["THIS_WORK(planned)", "verifier allow AND executed op_id != op(pi) (binding-soundness oracle)", "gateway x verifier placement x framework",
                    "DPoP htm/htu/ath/jti (+ trust headers)", "edge / origin / both", "planned public harness"])
    inc = sum(1 for r in rows if r["decision"] == "include"); bg = sum(1 for r in rows if r["decision"] == "background")
    print(f"screened={len(rows)} include={inc} background={bg} exclude={len(rows)-inc-bg}")

if __name__ == "__main__":
    main()
