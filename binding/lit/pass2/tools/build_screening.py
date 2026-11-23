"""Builds ../screening.csv (pass 2). Same columns as pass 1: id,title,authors,venue,year,url,stage,decision,reason.
stage: FT = full text read; MD = metadata/abstract/landing/advisory page read; TA = title(/snippet) only; SPEC = standard text read.
decision: include = bears on a claim (see NOVELTY_UPDATE.md); background = context; exclude = screened out (E-codes as protocol.md §4).
Reason tags: [claims: ...] maps to C1 binding-soundness property, C2 G1 proof-bound dispatch, C3 G2 under A_leak,
C4 E4 authorization soundness, C5 A1 claim ablation, C6 D-A/D-B defence. [found via: ...] as in pass 1."""
import csv, pathlib
R = []
def add(title, authors, venue, year, url, stage, decision, reason):
    R.append([title, authors, venue, year, url, stage, decision, reason])

# ---------------- practitioner research (talks, white papers, blogs) ----------------
add("Breaking Parser Logic! Take Your Path Normalization Off and Pop 0days Out", "Orange Tsai (Cheng-Da Tsai)", "Black Hat USA 2018 / DEF CON 26 (talk + slides)", 2018,
    "https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf", "FT", "include",
    "Slides read in full: frames the bug as 'if (check(data)) use(data)' inconsistency; reverse-proxy vs Java backend table (';' path params stripped by Tomcat/Jetty, kept by nginx/Apache/IIS); '/..;/' ACL bypass (Uber, Bynder), Nuxeo ACL-vs-container table; CVE-2018-1271 Spring. Pre-empts the 'checker view != executor view' insight and E4 RC5 (';') [claims: C1,C3,C4] [found via: websearch]")
add("Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server", "Orange Tsai", "Black Hat USA 2024 (talk) + DEVCORE blog", 2024,
    "https://devco.re/blog/2024/08/09/confusion-attacks-exploiting-hidden-semantic-ambiguity-in-apache-http-server-en/", "MD", "include",
    "Blog outline + 'Primitive 1-2 ACL Bypass' section read: auth/ACL bypass from inconsistent semantics of r->filename across httpd modules (mod_proxy vs auth modules); intra-server module differential, same check/use split [claims: C1,C4] [found via: websearch]")
add("A New Attack Surface on Microsoft Exchange: ProxyShell (CVE-2021-34473 path confusion)", "Orange Tsai (talk); ZDI write-up", "Black Hat USA 2021 (talk); ZDI blog", 2021,
    "https://www.thezdi.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell", "TA", "background",
    "Search snippets only (slides not fetched): frontend/backend path confusion in Exchange Explicit Logon reaches backend as privileged; canonical frontend-auth/backend-execute split in a commercial product [claims: C1,C3] [found via: websearch]")
add("Gotta Cache 'em all: bending the rules of web cache exploitation", "Martin Doyhenard", "Black Hat USA 2024 / DEF CON 32 (white paper)", 2024,
    "https://portswigger.net/kb/papers/kapvrid/gotta-cache-em-all.pdf", "FT", "include",
    "White paper read: delimiter discrepancies (';' Spring, '.' Rails, %00, %0a nginx rewrite), decoding and dot-segment normalisation discrepancies between cache and origin; cache oracle not authz, but primitive catalogue overlaps our G2 primitives [claims: C3] [found via: websearch]")
add("HTTP/1.1 Must Die: The Desync Endgame", "James Kettle", "Black Hat USA 2025 (white paper)", 2025,
    "https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-wp.pdf", "FT", "background",
    "White paper fetched and grepped: request-framing desync, not path/ACL; supports 'differential-first' framing only [claims: C3] [found via: websearch]")
add("Path traversal in authorization context in Kong and F5 NGINX", "xvnpw (Marcin Niemiec)", "Personal blog (research series)", 2021,
    "https://xvnpw.github.io/posts/path_traversal_in_authorization_context_in_kong_and_f5_nginx/", "FT", "include",
    "Read in full: Kong custom external-auth plugin forwarding ngx.var.request_uri / kong.request.get_path() (both un-normalised) -> '/public/../protected' bypass on Kong 2.6; Kong decodes %2E not %2F; F5 NGINX IC same. This IS our E4 RC2 configuration (raw $request_uri to PDP, normalised upstream), published 2021 [claims: C4,C3] [found via: task brief;websearch]")
add("CVE-2021-43557: Apache APISIX: Path traversal in request_uri variable", "xvnpw (Marcin Niemiec)", "Personal blog (research series)", 2021,
    "https://xvnpw.github.io/posts/cve_2021_43557_apache_apisix_path_traversal_in_request_uri_variable/", "FT", "include",
    "Read in full: uri-blocker matched raw ctx.var.request_uri; '/public/../protected' and '..%2F' bypass on APISIX 2.10; notes authz-keycloak also consumes request_uri; Skipper not exploitable (uses normalised path) [claims: C3,C4,C6] [found via: websearch]")
add("Path traversal in authorization context in Traefik and HAProxy", "xvnpw (Marcin Niemiec)", "Personal blog (research series)", 2021,
    "https://xvnpw.github.io/posts/path_traversal_in_authorization_context_in_traefik_and_haproxy/", "FT", "include",
    "Read: Traefik ForwardAuth and haproxy-ingress NOT exploitable in 2021 because neither normalises before forwarding (one representation) - same reason our W13 found 0 G2 on HAProxy [claims: C3,C4] [found via: snowball:xvnpw series]")
add("Path traversal in authorization context in Emissary", "xvnpw (Marcin Niemiec)", "Personal blog (research series)", 2021,
    "https://xvnpw.github.io/posts/path_traversal_in_authorization_context_in_emissary/", "FT", "include",
    "Read: Emissary/Envoy normalize_path=true + path_with_escaped_slashes_action=KEEP_UNCHANGED gives auth service and router the same normalised path -> no bypass; the 'same view for check and route' remedy = our D-A principle [claims: C6,C4] [found via: snowball:xvnpw series]")
add("External Authentication bypass in ingress-nginx", "xvnpw (Marcin Niemiec)", "Personal blog; HackerOne #1357948 (closed informative); kubernetes/ingress-nginx#8644", 2022,
    "https://xvnpw.github.io/posts/external_authentication_bypass_in_ingress_nginx/", "FT", "include",
    "Read: nginx auth_request sends X-Original-Url/X-Auth-Request-Redirect from raw $request_uri; '/public/..%2Fprotected' bypass; Kubernetes triaged it as not a security issue and nginx said raw $request_uri is obviously un-normalised -> vendors classify our E4 class as documented behaviour [claims: C4,C3] [found via: snowball:xvnpw series]")
add("Bug bounty tips for nginx $request_uri path traversal bypass", "xvnpw (Marcin Niemiec)", "Personal blog (research series)", 2021,
    "https://xvnpw.github.io/posts/bug_bounty_tips_for_nginx_request_uri_path_traversal_bypass/", "FT", "include",
    "Read: methodology incl. 'privilege escalation: valid JWT + traversal to endpoint you cannot access' = our A_client E4 threat model (valid credential, path policy split) [claims: C4] [found via: snowball:xvnpw series]")
add("Hunting for buggy authentication/authorization services on github", "xvnpw (Marcin Niemiec)", "Personal blog (research series)", 2021,
    "https://xvnpw.github.io/posts/hunting_for_buggy_authentication_authorization_services_on_github/", "FT", "background",
    "Read: Pomerium/Authelia/external-auth-server take X-Original-Url un-normalised into path policies (code-level, not exploited end-to-end) - PDP side of E4 [claims: C4] [found via: snowball:xvnpw series]")
add("Reverse proxies & Inconsistency", "Aleksei Tiurin (GreenDog), Acunetix", "ZeroNights 2018 / OWASP Malta (slides)", 2018,
    "https://speakerdeck.com/greendog/reverse-proxies-and-inconsistency", "TA", "background",
    "Slide deck landing page + search summaries only: proxy/backend path parsing inconsistencies used to bypass proxy restrictions (incl. ';' WebLogic/Tomcat, '..') [claims: C3,C4] [found via: websearch]")
add("Tomcat path traversal via reverse proxy mapping (scanner check)", "Acunetix / Invicti", "Vulnerability KB page", 2019,
    "https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/", "MD", "background",
    "Page read via search summary: '/..;/' normalised by Tomcat, forwarded verbatim by proxies; productised scanner check = class is commodity knowledge [claims: C4] [found via: websearch]")
add("CVE-2025-0108: PAN-OS auth bypass via Nginx/Apache path confusion", "Assetnote / Searchlight Cyber", "Research blog", 2025,
    "https://slcyber.io/blog/nginx-apache-path-confusion-to-auth-bypass-in-pan-os", "TA", "background",
    "Title + search summary: nginx-vs-Apache path interpretation differential gives auth bypass in a commercial appliance [claims: C3,C4] [found via: websearch]")
add("proxy_pass: nginx's dangerous URL normalization of paths", "Joshua Rogers", "Personal blog", 2025,
    "https://joshua.hu/proxy-pass-nginx-decoding-normalizing-url-path-dangerous", "TA", "background",
    "Search summary only: proxy_pass with a URI part decodes/normalises the path before forwarding; complements our 'nginx forwards raw #/%2f' enabler [claims: C3] [found via: websearch]")
add("Splitting the Email Atom", "Gareth Heyes", "Black Hat USA 2024 / DEF CON 32 (PortSwigger research)", 2024,
    "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024-nominations-open", "TA", "exclude",
    "E5: parser-discrepancy-to-access-control, but email address parsing, not HTTP request view [found via: websearch]")
add("Web cache deception (Web Security Academy topic)", "PortSwigger", "Web Security Academy", 2024,
    "https://portswigger.net/web-security/web-cache-deception", "TA", "exclude", "E4/E3: tutorial version of Doyhenard 2024 [found via: websearch]")

# ---------------- academic ----------------
add("Be Aware of What You Let Pass: Demystifying URL-based Authentication Bypass Vulnerability in Java Web Applications", "Qiyi Zhang; Fengyu Liu; Zihan Lin; Yuan Zhang", "ACM CCS 2025", 2025,
    "https://doi.org/10.1145/3719027.3765199", "FT", "include",
    "Full text (author PDF) read: 53 real UABVulns; root cause = inconsistency between routing features (relative-path, semicolon, case-insensitive, multiple slashes, trailing slash, suffix, decoding: 13 features, Table 2) and string-matching auth checks (startsWith/endsWith/contains); UABScan static analysis, 94 vulns / 31 CVEs; mitigation = sanitize to the router's normal form before checking. One-to-one with E4 RC1/RC3/RC4/RC5/RC6 mechanisms (in-app instead of gateway PDP) [claims: C4,C1,C6] [found via: websearch;dblp:sparql]")
add("Breaking the Gate: Detecting Invisible Authentication Slip-Through in NGINX Reverse Proxy", "Aliakbar Sadeghi; Maryam Rostamipoor; Sai Chand Boyapati; Omar Chowdhury", "ACM CCS 2026 (pp. 5284-5298)", 2026,
    "https://doi.org/10.1145/3830454.3846523", "MD", "include",
    "Abstract (Semantic Scholar) read; full text not accessible (ACM DL 403): NginxBuster, 7 classes of config-semantic nginx auth bypass from location ordering, map resolution, URI normalisation, per-block access control; static + active validation; 1,344 GitHub configs, 11.8% flagged, 144 confirmed. Concurrent work on our nginx auth_request placement; unauthenticated-bypass oracle, no PoP [claims: C4,C3,C1] [found via: venue list:CCS2026;crossref;s2]")
add("Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards", "Pedram Hosseyni; Ralf Küsters; Tim Würtele", "IEEE S&P 2026", 2026,
    "https://doi.org/10.1109/SP63933.2026.00116", "MD", "include",
    "Abstract read (closed access): signed client-authentication assertions accepted at an endpoint other than intended because audience binding is ambiguous across >=2 endpoints; disclosed to OAuth/OIDF, standards being updated. Same group as the FAPI formal model; structurally the closest 'valid signed artefact accepted for X, used for Y' analogue to A_leak [claims: C1,C3,C5] [found via: venue list:S&P2026;s2]")
add("403 Forbidden? Ethically Evaluating Broken Access Control in the Wild", "Saiid El Hajj Chehade; Florian Hantke; Ben Stock", "IEEE S&P 2025", 2025,
    "https://doi.org/10.1109/SP61157.2025.00252", "MD", "background",
    "Abstract/landing read: Variable Swapping Framework, black-box BAC (IDOR-type) testing with two own accounts; oracle = cross-account access, no parsing differential [claims: C4] [found via: dblp:sparql;websearch]")
add("yoU aRe a Liar://A Unified Framework for Cross-Testing URL Parsers", "Dashmeet Kaur Ajmani; Igibek Koishybayev; Alexandros Kapravelos", "IEEE SPW 2022 (LangSec)", 2022,
    "https://doi.org/10.1109/SPW54247.2022.9833883", "MD", "background",
    "Abstract: cross-tests URL parsers, 7 inconsistency categories, SOP-oriented prioritisation; primitive source for URL-level differentials [claims: C3] [found via: dblp:sparql]")
add("A Survey of Parser Differential Anti-Patterns", "(SPW 2023 authors; not re-checked)", "IEEE SPW 2023", 2023,
    "https://doi.org/10.1109/SPW59333.2023.00016", "TA", "background",
    "Title + Crossref only: general parser-differential taxonomy; cite only if the paper needs a LangSec anchor [claims: C3] [found via: dblp:sparql]")
add("Parse Me, Baby, One More Time: Bypassing HTML Sanitizer via Parsing Differentials", "David Klein; Martin Johns", "IEEE S&P 2024", 2024,
    "https://doi.org/10.1109/SP54263.2024.00177", "TA", "background",
    "Title + citation context in UABScan: sanitizer vs browser parser differential; same check/use-parser split, different domain [claims: C1] [found via: dblp:sparql;snowball:UABScan refs]")
add("PathFault: Automated Exploit Generator for Web Services via HTTP Message Parser Discrepancies", "Juryeok Kim; Youngjoo Shin", "ICISC 2025 (LNCS, published 2026)", 2025,
    "https://doi.org/10.1007/978-981-95-8034-7_6", "TA", "include",
    "Title + Crossref + S2 metadata only (no abstract available): automated exploit generation from HTTP parser discrepancies in web services; possible overlap with G2 path primitives -> must be read before camera-ready [claims: C3] [found via: dblp:sparql]")
add("SPCA: Stream Parser Confusion Attack for Web Application Firewall Evasion in HTTP/2", "Kyungrok Choi; Woonghee Lee; Junbeom Hur", "WWW 2026", 2026,
    "https://doi.org/10.1145/3774904.3792517", "MD", "background",
    "Abstract read: WAF vs backend HTTP/2 stream-priority parsing discrepancy delivers unmodified payloads past inspection; check-vs-execute split for content WAFs (WAFFLED lineage) [claims: C3] [found via: dblp:sparql]")
add("H3Act: Automated Measuring Semantic Conversion Anomalies of HTTP/3-to-HTTP/1.1 Translation in CDNs", "Qihang Peng; Siyuan Tian; Yongxin Qiu; et al.", "USENIX Security 2026", 2026,
    "https://www.usenix.org/conference/usenixsecurity26/technical-sessions", "MD", "background",
    "Abstract read on program page: LLM+RAG fuzzing of H3->H1 conversion in 9 CDNs; smuggling/cache poisoning/DoS; no authz/PoP oracle [claims: C3] [found via: venue list:USENIX Sec 2026]")
add("HTTP Conformance vs. Middleboxes: Identifying Where the Rules Actually Break Down", "Iliès Benhabbour; Mahmoud Attia; Marc Dacier", "PAM 2025", 2025,
    "https://doi.org/10.1007/978-3-031-85960-1_7", "TA", "background", "Title + Crossref: middlebox HTTP conformance measurement [claims: C3] [found via: dblp:sparql]")
add("Web Cache Deception Escalates!", "Seyed Ali Mirheidari; Matteo Golinelli; Kaan Onarlioglu; Engin Kirda; Bruno Crispo", "USENIX Security 2022", 2022,
    "https://www.usenix.org/conference/usenixsecurity22/presentation/mirheidari", "TA", "background",
    "Title/landing: path-confusion WCD follow-up to Cached and Confused (pass 1); same Kirda/Crispo neighbour groups [claims: C3] [found via: dblp:sparql]")
add("When POST Becomes GET: Investigating HTTP Method Interchangeability and Its Security Implications", "Matteo Golinelli; Seif Errahmane Hannachi; Bruno Crispo", "ACSAC 2026 (accepted)", 2026,
    "https://www.acsac.org/2026/program/papers/", "MD", "include",
    "UPDATE to pass-1 S0xx (arXiv 2610.37474, FT in pass 1): now a peer-reviewed ACSAC 2026 paper per accepted list. G1 method claim must cite the ACSAC version [claims: C2] [found via: venue list:ACSAC2026]")
add("Beyond Proof of Possession: A Relational Theory of Authority", "Nicola Gallo", "arXiv 2611.07159 (cs.CR)", 2026,
    "https://arxiv.org/abs/2611.07159", "MD", "background",
    "Abstract read: argues PoP establishes artefact control but not authorization of an execution occurrence; conceptual/formal, no HTTP; extends pass-1 gallo2026continuity. Cite for 'PoP != operation authorization' only as conceptual precedent [claims: C1] [found via: arxiv:all:\"proof-of-possession\"]")
add("Access Control as Verified Parse Constraints", "Saranachon Iammongkol; Zhiyi Huang; David Eyers", "arXiv 2609.12488 (cs.CR)", 2026,
    "https://arxiv.org/abs/2609.12488", "MD", "background",
    "Abstract read: verified EverParse recognizer for bounded gateway policy decision functions; addresses gateway enforcement-code bugs, assumes a single parse -> orthogonal to cross-component view splits [claims: C6] [found via: arxiv:cat:cs.CR authorization gateway]")
add("Layer Order Semantics for Automata-Based Cybersecurity", "Faruk Alpay; Taylan Alpay", "arXiv 2606.10649 (cs.CR)", 2026,
    "https://arxiv.org/abs/2606.10649", "MD", "background",
    "Abstract read: formal layer-order automata; worked case HTTP desync front/back-end parser pairs; theoretical, no measurement [claims: C1] [found via: arxiv:all:\"parser differential\"]")
add("Hard-Earned Lessons in Access Control at Scale: Enforcing Identity and Policy Across Trust Boundaries with Reverse Proxies and mTLS", "(not re-checked)", "arXiv 2508.01863", 2025,
    "https://doi.org/10.48550/ARXIV.2508.01863", "TA", "background", "Title only (dblp): practitioner experience report on proxy-enforced identity/policy; possible G3 context [claims: C4] [found via: dblp:sparql]")
add("BACGUARD: Fact-Grounded Runtime Mitigation of Broken Access Control", "Moses Ndebugre", "arXiv 2611.10157", 2026, "https://arxiv.org/abs/2611.10157", "MD", "exclude",
    "E5: reverse-proxy BAC enforcement via DB joins; no view differential [found via: arxiv:cat:cs.CR reverse proxy]")
add("Suspected Until Inspected: Neuro-Symbolic Detection of Broken Access Control in Server-Side Web Applications", "Chengyao Yang; Zifeng Kang; Dongqi Han; Shihong Zou", "arXiv 2611.27270", 2026, "https://arxiv.org/abs/2611.27270", "MD", "exclude",
    "E5: missing-check BAC detection (FLINT); no routing/parsing differential [found via: arxiv:broken access control]")
add("ABSENTIA: Detecting Broken Access Control Vulnerabilities in Web Applications", "André V. Duarte; et al.", "arXiv 2610.00977", 2026, "https://arxiv.org/abs/2610.00977", "MD", "exclude",
    "E5: LLM-agent BAC auditing; no differential [found via: arxiv:broken access control]")
add("Repairing Broken Access Control in Web Applications with LLMs: An Empirical Benchmark Study", "(not re-checked)", "arXiv 2610.34290", 2026, "https://arxiv.org/pdf/2610.34290", "TA", "exclude", "E5 [found via: websearch]")
add("BACFuzz: Exposing the Silence on Broken Access Control Vulnerabilities in Web Applications", "(not re-checked)", "arXiv 2507.15984", 2025, "https://doi.org/10.48550/ARXIV.2507.15984", "TA", "exclude", "E5: BAC fuzzing, no view split [found via: dblp:sparql]")
add("Trust Boundary Semantic Gaps: A Multi-dimensional Analysis and Mitigation for Security-by-Design", "Doyeon Kim; J. Choi; Junghee Lee", "arXiv 2607.01711", 2026, "https://doi.org/10.48550/ARXIV.2607.01711", "MD", "exclude",
    "E4: duplicate of pass-1 kim2026tbsg [found via: dblp:sparql]")
add("Web Application Vulnerability Repair via Context-Aware Fault Localization and Directed Differential Fuzzing", "(not re-checked)", "IEEE S&P 2026", 2026, "https://sp2026.ieee-security.org/accepted-papers.html", "TA", "exclude", "E5: 'differential' = patch differential [found via: venue list:S&P2026]")
add("Demystifying the (In)Security of OAuth-based Account Linking in Connector Ecosystems", "(not re-checked)", "IEEE S&P 2026", 2026, "https://sp2026.ieee-security.org/accepted-papers.html", "TA", "exclude", "E5: OAuth client/linking flows, no RS-side PoP [found via: venue list:S&P2026]")
add("Mini-Programs, Mega-Problems: Unveiling OAuth-based Authentication Misuses in Mini-Programs via Dynamic Analysis", "(not re-checked)", "ACM CCS 2026", 2026, "https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html", "TA", "exclude", "E5 [found via: venue list:CCS2026]")
add("eMicro: Real-Time Multi-Hop Access Control for Microservices with eBPF", "Rizky Ramadhana Putra; Osama Bajaber; Saimon Amanuel Tsegai; et al.", "ACM CCS 2026", 2026, "https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html", "TA", "background",
    "Title only: multi-hop microservice access control; possible placement-related related work, no evidence of view differential [claims: C6] [found via: venue list:CCS2026]")
add("PORTA: Systematic Discovery of Vulnerabilities in Identity Brokers", "Zixu Zhou; Xiangyu Guo; Ilya Grishchenko; David Lie", "ACM CCS 2026", 2026, "https://www.sigsac.org/ccs/CCS2026/program/schedule.html", "TA", "exclude", "E5: identity brokers (title only) [found via: venue list:CCS2026]")
add("Reproducing Web Application Vulnerabilities with Patch-Guided Routing Inference and Sink Exploration", "Youkun Shi; Yuan Zhang; Feng Xue; Jiarun Dai; et al.", "ACM CCS 2026", 2026, "https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html", "TA", "exclude", "E5: vuln reproduction (UABScan group; title only) [found via: venue list:CCS2026]")
add("Through the Authentication Maze: Detecting Authentication Bypass Vulnerabilities in Firmware Binaries", "(not re-checked)", "NDSS 2026", 2026, "https://www.ndss-symposium.org/ndss2026/accepted-papers/", "TA", "exclude", "E5: firmware binaries [found via: venue list:NDSS2026;dblp:sparql]")
add("Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery", "(NDSS 2026)", "NDSS 2026", 2026, "https://www.ndss-symposium.org/ndss2026/accepted-papers/", "TA", "exclude", "E4: = pass-1 yang2026jwteemo (JWTeemo) [found via: venue list:NDSS2026]")
add("Opossum Attack: Application Layer Desynchronization using Opportunistic TLS", "Merget et al.", "USENIX Security 2026", 2026, "https://www.usenix.org/conference/usenixsecurity26/technical-sessions", "TA", "exclude", "E5: TLS-layer desync [found via: venue list:USENIX2026;dblp:sparql]")
add("Plaintext Recovery Against Post-Filtering Access Control", "Zachary Espiritu; David Cash; et al.", "USENIX Security 2026", 2026, "https://www.usenix.org/conference/usenixsecurity26/technical-sessions", "TA", "exclude", "E1/E5: encrypted search access control [found via: venue list:USENIX2026]")
add("RESTGuardian: Automated Black-Box Fuzzing for RESTful API via Efficient Dependency Inference and Deep Vulnerability Detection", "(not re-checked)", "ACM CCS 2026", 2026, "https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html", "TA", "exclude", "E5: REST fuzzing, no PoP/view split (title) [found via: venue list:CCS2026]")
add("RESTing-LLAMA: Large Language Model based REST API Fuzzing", "(not re-checked)", "ACM AsiaCCS 2026", 2026, "https://asiaccs2026.cse.iitkgp.ac.in/cycle-1-papers/", "TA", "exclude", "E5 [found via: venue list:AsiaCCS2026]")
add("Stateless 2PC Signatures for Internet-Scale Authentication and Authorization", "(not re-checked)", "ACM AsiaCCS 2026", 2026, "https://asiaccs2026.cse.iitkgp.ac.in/cycle-1-papers/", "TA", "exclude", "E5: signature scheme [found via: venue list:AsiaCCS2026]")
add("Phoebus: Automated Cross-Browser Differential Testing for Uncovering Security and Functional Bugs", "(not re-checked)", "ACSAC 2026", 2026, "https://www.acsac.org/2026/program/papers/", "TA", "exclude", "E5: browsers [found via: venue list:ACSAC2026]")
add("Finding and Exploiting Discrepancies in QR Code Payload Processing", "(not re-checked)", "ACM CCS 2026", 2026, "https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html", "TA", "exclude", "E5: QR parsing [found via: venue list:CCS2026]")
add("Email Smuggling with Differential Fuzzing of MIME Parsers", "(not re-checked)", "IEEE SPW 2025", 2025, "https://doi.org/10.1109/SPW67851.2025.00007", "TA", "exclude", "E5: MIME [found via: dblp:sparql]")
add("Internet's Invisible Enemy: Detecting and Measuring Web Cache Poisoning in the Wild", "(not re-checked)", "ACM CCS 2024", 2024, "https://doi.org/10.1145/3658644.3690361", "TA", "exclude", "E6: cache poisoning, primitive source superseded for our purposes [found via: dblp:sparql]")
add("A Methodology for Web Cache Deception Vulnerability Discovery", "(not re-checked)", "CLOSER 2024", 2024, "https://doi.org/10.5220/0012692000003711", "TA", "exclude", "E6 [found via: dblp:sparql]")
add("Eradicating the Unseen: Detecting, Exploiting, and Remediating a Path Traversal Vulnerability across GitHub", "(not re-checked)", "ACM AsiaCCS 2025", 2025, "https://doi.org/10.1145/3708821.3736220", "TA", "exclude", "E5: file-system path traversal, not request-view split [found via: dblp:sparql]")

# ---------------- standards ----------------
add("A Method for Signing HTTP Requests for OAuth (draft-ietf-oauth-signed-http-request-03)", "Justin Richer; John Bradley; Hannes Tschofenig", "IETF OAuth WG Internet-Draft (expired Feb 2017)", 2016,
    "https://datatracker.ietf.org/doc/draft-ietf-oauth-signed-http-request/03/", "SPEC", "include",
    "Read in full: PoP-signed request object with OPTIONAL m (method), u (host), p (path), q (hashed query map), h (hashed headers), b (body hash). Query/header/body binding for OAuth PoP was specified in 2016 and abandoned; zero mentions of proxies/intermediaries. Pass 1 missed it. Pre-empts the DESIGN of A1 +query/+digest [claims: C5,C2] [found via: targeted check (A1 design lineage)]")

# ---------------- advisories / CVE families ----------------
add("ISTIO-SECURITY-2021-008: CVE-2021-39156 (Envoy CVE-2021-32779) fragment in path bypasses path-based AuthorizationPolicy", "Istio / Envoy maintainers", "Security bulletin", 2021,
    "https://istio.io/latest/news/security/istio-security-2021-008/", "MD", "include",
    "Bulletin read: '/user/profile#section1' bypasses DENY '/user/profile' and reaches backend as '/user/profile%23section1'; fix = strip fragment before authz AND routing. Same class as our '#' G2 mechanism (kill RC6/X1) with a path ACL instead of a DPoP htu; also CVE-2021-39155 host case-folding [claims: C3,C6] [found via: websearch]")
add("CVE-2021-29492: Envoy escaped-slash (%2F) paths bypass access control", "Envoy maintainers / NVD", "Security advisory (GHSA-4987-27fx-x6cf)", 2021,
    "https://nvd.nist.gov/vuln/detail/CVE-2021-29492", "MD", "include",
    "Content via Red Hat/Snyk/Istio-2021-005 mirrors (NVD renders client-side): '/something%2F..%2Fadmin' bypasses '/admin' block incl. ext_authz; fix adds escaped-slash normalisation option. Encoded-slash class = APISIX RC-W13-A family [claims: C3,C4] [found via: websearch]")
add("CVE-2026-73551 (GHSA-2w8w-rfw7-8gg4): Envoy normalisation ignores dot/dot-dot segments with ';' parameters", "Envoy maintainers", "Security advisory (OSV)", 2026,
    "https://osv.dev/vulnerability/CVE-2026-73551", "MD", "include",
    "OSV record read: '/user/..;foo=bar/admin' not canonicalised; RBAC/route vs RFC-3986 upstream mismatch; fixed 1.36.10/1.37.6/1.38.4/1.39.1 (our pin v1.39.6 is post-fix) [claims: C3,C4] [found via: websearch]")
add("ISTIO-SECURITY-2026-006: Envoy CVE-2026-73511 (per-segment parameters path matching), CVE-2026-73553 (ignore_path_parameters_in_path_matching '/admin;x' RBAC bypass), CVE-2026-73552", "Istio / Envoy maintainers", "Security bulletin", 2026,
    "https://istio.io/latest/news/security/istio-security-2026-006/", "MD", "include",
    "Bulletin read (2026-08-27): three 2026 Envoy path-parameter/regex authz-vs-backend mismatch CVEs; ';' class is still producing CVEs in current releases [claims: C3,C4] [found via: websearch]")
add("Re: Double URL Decoding Mismatch Between Edge and Origin Envoy Enables Routing Bypass (Google VRP)", "Envoy security team (Y. Avlasov)", "envoy-security-announce thread", 2026,
    "https://groups.google.com/g/envoy-security-announce/c/9eSF1kGUpSk", "TA", "background",
    "Search summary only: edge Envoy decodes once before routing policy, origin decodes again -> double-encoded traversal reaches /blockedz; attributed to config not normalising (no CVE) [claims: C3] [found via: websearch]")
add("CVE-2026-40912 (GHSA-6jwx-7vp4-9847): Traefik StripPrefixRegex Path/RawPath desync -> ForwardAuth sees dot-segment path", "Traefik maintainers", "Security advisory (GitLab mirror)", 2026,
    "https://advisories.gitlab.com/golang/github.com/traefik/traefik/v3/CVE-2026-40912/", "MD", "include",
    "Advisory read (pass 1 had it from secondary sources): ForwardAuth receives wrong X-Forwarded-Uri, backend normalises dot segment and serves protected path; fixed 3.6.14/3.7.0-rc.2 [claims: C3,C4] [found via: prior review;websearch]")
add("CVE-2026-88009 (GHSA-f52w-8j3h-j724): Traefik rootless/opaque HTTP/1 request-target routed as '/' but forwarded verbatim", "Traefik maintainers", "Security advisory (GitLab mirror)", 2026,
    "https://advisories.gitlab.com/golang/github.com/traefik/traefik/v2/CVE-2026-88009/", "MD", "include",
    "Advisory read: forwardAuth denying ^/admin returns ALLOW for 'GET http:http://internal-vhost/admin'; routing/forwardAuth/encodedCharacters/access log all see '/'; fixed v3.7.13 (our pin v3.7.19 post-fix). Directly relevant to the GATE_DECISION open item 'absolute-form target not in E4 battery' [claims: C3,C4] [found via: websearch]")
add("CVE-2026-48020: Traefik StripPrefix route-level auth bypass; CVE-2026-65600 ReplacePathRegex; CVE-2025-66490 router path normalisation bypass", "Traefik maintainers", "Security advisories (GitLab mirror / NVD)", 2026,
    "https://advisories.gitlab.com/golang/github.com/traefik/traefik/v3/CVE-2026-48020/", "MD", "include",
    "Advisory titles/summaries read: a 2025-2026 series of Traefik path-normalisation authz bypasses; establishes that gateway-side view/route splits are an actively-patched CVE family [claims: C3,C4] [found via: websearch]")
add("CVE-2021-43557: Apache APISIX uri-block path traversal via request_uri", "Apache APISIX", "Security advisory / project blog", 2021,
    "https://apisix.apache.org/blog/2021/11/23/cve-2021-43557/", "MD", "include", "Project page 200; fix 2.10.2; see xvnpw write-up [claims: C3,C4] [found via: websearch]")
add("CVE-2026-94269: Apache APISIX servlet-style normalization creates a route/upstream authorization mismatch", "Apache APISIX (reporter: Ziyue)", "oss-security announcement", 2026,
    "https://www.openwall.com/lists/oss-security/2026/10/01/7", "MD", "include",
    "Announcement read: crafted encoded path reaches an upstream endpoint the matched route's policies do not cover; 2.14.1-3.18.0, fixed 3.19.0 [claims: C3,C4] [found via: websearch]")
add("CVE-2026-124680: Apache APISIX route-level authentication bypass via path normalization mismatch between routing and upstream forwarding", "Apache APISIX (reporter: Uttej Badwane)", "oss-security announcement + PR #14035", 2026,
    "https://www.openwall.com/lists/oss-security/2026/11/13/7", "MD", "include",
    "Announcement + PR #14035 + init.lua@3.21.0 L643-662 read: router matched nginx-normalised $uri, upstream got raw request line; fix forwards matched path ONLY when nginx did more than percent-decode/merge slashes, so '%2F' is deliberately still forwarded raw. This is the upstream half of our RC-W13-A; RC-W13-A is NOT a new class (see NOVELTY_UPDATE) [claims: C3,C6] [found via: websearch;github source]")
add("Apache APISIX 3.20.0 fixes seven gateway auth bypasses (CVE-2026-124680/124679/124666/124716/124723/124726/124719)", "Corgea research", "Vendor blog (secondary)", 2026,
    "https://corgea.com/research/cve-2026-124680-124679-124666-124716-124723-124726-124719-apache-apisix-3-20-0-auth-bypass-november-2026", "MD", "background",
    "TL;DR and technical analysis §1-3 read; secondary analysis of the APISIX 3.20.0 CVEs incl. forward-auth allow_degradation spoofed upstream headers (G3-type) and match_uri_encoded_slash mTLS skip; code claims cross-checked against GitHub for CVE-2026-124680 [claims: C3,C4] [found via: websearch]")
add("CVE-2021-27306: Kong Gateway JWT plugin authenticated-route bypass (URI normalisation before route matching)", "Kong / NVD", "Security advisory", 2021,
    "https://nvd.nist.gov/vuln/detail/CVE-2021-27306", "TA", "background",
    "NVD description via aggregators; path-normalisation link only from a secondary source (Wiz) [claims: C4] [found via: websearch]")
add("CVE-2026-105986: Kong Gateway Enterprise RBAC self-escalation via percent-encoded Admin API path", "Kong", "Security advisory", 2026,
    "https://developer.konghq.com/support/security/security-advisory-cve-2026-105986/", "TA", "background", "Advisory page 200 (search summary): encoded-path authz check bypass on Admin API; same family, different surface [claims: C4] [found via: websearch]")
add("CVE-2016-5007: Spring Security / Spring MVC path matching inconsistency", "Pivotal / Spring", "Security advisory", 2016,
    "https://spring.io/security/cve-2016-5007", "MD", "include",
    "Advisory summary read: Spring Security and Spring MVC match paths with different strictness (e.g. token trimming) -> protected controllers treated as unprotected; fix = MvcRequestMatcher (check with the router's matcher). Canonical early instance of E4 + D-A remedy [claims: C4,C6] [found via: websearch]")
add("CVE-2023-34034: Spring Security WebFlux '**' pattern mismatch between Security and WebFlux", "Spring", "Security advisory", 2023,
    "https://spring.io/security/cve-2023-34034", "TA", "background", "Summary only: security matcher vs router matcher mismatch, recurring in 2023 [claims: C4] [found via: websearch]")
add("CVE-2026-42274 (GHSA-3q34-rx83-r6mq): Heimdall authorization bypass via path normalization mismatch", "dadrus/heimdall maintainers", "Security advisory (GitLab mirror)", 2026,
    "https://advisories.gitlab.com/golang/github.com/dadrus/heimdall/CVE-2026-42274/", "MD", "include",
    "Advisory title + summary: identity-aware-proxy/PDP matched rules on raw path without RFC 3986 dot-segment removal while downstream normalises; fixed 0.17.14 by normalising before rule evaluation. A PDP-side E4 instance in a 2026 CVE [claims: C4,C6] [found via: websearch]")
add("CVE-2026-33494 (GHSA-p224-6x5r-fjpm): Ory Oathkeeper authorization bypass via HTTP path traversal", "Ory maintainers", "Security advisory (GitLab mirror)", 2026,
    "https://advisories.gitlab.com/golang/github.com/ory/oathkeeper/CVE-2026-33494/", "MD", "include",
    "Advisory title + summary: rule evaluation on raw path; traversal URL matched to permissive rule resolves to protected path. Same as Heimdall [claims: C4] [found via: websearch]")
add("CVE-2025-29927: Next.js middleware authorization bypass via x-middleware-subrequest", "Vercel / NVD", "Security advisory", 2025,
    "https://nvd.nist.gov/vuln/detail/CVE-2025-29927", "TA", "background",
    "Vendor/aggregator summaries: client-supplied internal header skips middleware authz entirely; G3 (trust-header) analogue inside one framework [claims: C4] [found via: websearch]")
add("CVE-2025-64484: oauth2-proxy underscore header variants bypass X-Forwarded-* stripping", "oauth2-proxy / NVD", "Security advisory", 2025,
    "https://nvd.nist.gov/vuln/detail/CVE-2025-64484", "TA", "background",
    "Aggregator summaries (Red Hat, Debian, Praetorian): filter checks hyphen form, upstream normalises '_'->'-'; header-name differential defeats trust-header stripping (G3 relevant; not in our G3 battery) [claims: C4] [found via: websearch]")
add("CVE-2026-2880: @fastify/middie authorization bypass via URL canonicalization drift", "(third-party report)", "cvereports.com (secondary)", 2026,
    "https://cvereports.com/reports/CVE-2026-2880", "TA", "background", "UNVERIFIED single secondary source; Node middleware vs router canonicalisation split [claims: C4] [found via: websearch]")
add("CVE-2026-39852: Quarkus path normalization authorization bypass", "(NVD)", "Security advisory", 2026,
    "https://nvd.nist.gov/vuln/detail/cve-2026-39852", "TA", "background", "UNVERIFIED: search-snippet description only [claims: C4] [found via: websearch]")
add("CVE-2023-45539: HAProxy accepts '#' in URI path component (fix: reject '#')", "HAProxy", "Security fix (pass-1 W16 triage)", 2023,
    "https://git.almalinux.org/rpms/haproxy/raw/branch/c8s/CVE-2023-45539-reject-pound-char-URI-component.patch", "TA", "background",
    "Already cited by W16 TRIAGE; listed so the '#' family is complete: '#' in path forwarded to backends treated as a vuln and fixed [claims: C3] [found via: disclosure/TRIAGE.md]")

out = pathlib.Path(__file__).resolve().parent.parent / "screening.csv"
with out.open("w", newline="") as f:
    w = csv.writer(f); w.writerow(["id", "title", "authors", "venue", "year", "url", "stage", "decision", "reason"])
    for i, r in enumerate(R, 1): w.writerow([f"P2-{i:03d}"] + r)
from collections import Counter
print(f"screened={len(R)}", dict(Counter(r[6] for r in R)), dict(Counter(r[5] for r in R)))
