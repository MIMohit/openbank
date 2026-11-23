"""Regenerate defence/patches/<fw>-defence-db.patch from the CURRENT executor sources.

Copies each executor into a temp a/ and b/ tree, adds the D-B module to b/ and makes the small
DEFENCE=db edits, then writes `diff -ruN a b`. It never touches harness/executors/. Each edit
asserts its anchor text occurs exactly once, so it fails loudly if an executor has drifted.

    cd binding/harness && python3 defence/patches/make_patches.py
    patch -p1 --dry-run < defence/patches/<fw>-defence-db.patch     # apply from binding/harness
"""
import pathlib
import shutil
import subprocess
import tempfile

H = pathlib.Path(__file__).resolve().parents[2]  # binding/harness
D = H / "defence"
IGNORE = shutil.ignore_patterns("node_modules", "conformance-out", "target", "bin", "obj", "__pycache__")

MODULES = {
    "fastapi": [(D / "fastapi/viewmac.py", "viewmac.py")],
    "express": [(D / "express/viewmac.js", "viewmac.js")],
    "spring": [(D / "spring/src/main/java/bench/defence/ViewMac.java", "src/main/java/bench/defence/ViewMac.java")],
    "aspnet": [(D / "aspnet/ViewMac/ViewMac.cs", "ViewMac.cs")],
}

EDITS = {
"fastapi": [
("app.py", "from starlette.exceptions import HTTPException as StarletteHTTPException\n",
 "from starlette.exceptions import HTTPException as StarletteHTTPException\n\nimport viewmac  # defence D-B (binding/harness/defence/fastapi/viewmac.py)\n"),
("app.py", 'if VERIFY_MODE not in ("off", "origin-raw", "origin-routed"):\n    sys.exit(f"bad VERIFY_MODE={VERIFY_MODE}")\n',
 '''if VERIFY_MODE not in ("off", "origin-raw", "origin-routed"):
    sys.exit(f"bad VERIFY_MODE={VERIFY_MODE}")
DEFENCE = os.environ.get("DEFENCE", "off").lower()
VIEW_MAC_KEY = os.environ.get("VIEW_MAC_KEY", "").encode()
if DEFENCE not in ("off", "db"):
    sys.exit(f"bad DEFENCE={DEFENCE}")
if DEFENCE == "db" and not VIEW_MAC_KEY:
    sys.exit("DEFENCE=db requires VIEW_MAC_KEY")
'''),
("app.py", '''    method = request.scope["method"]
    if VERIFY_MODE != "off":''', '''    method = request.scope["method"]
    if DEFENCE == "db":  # D-B: X-Verified-View must match the view this executor dispatched on
        res = viewmac.check(VIEW_MAC_KEY, [v for k, v in bh["headers"] if k == viewmac.HEADER],
                            [v for k, v in bh["headers"] if k == "dpop"], method, template, params)
        if not res.ok:
            bh["denied"] = True
            return JSONResponse({"op_id": op_id, "framework": FRAMEWORK, "denied": True, "reason": res.reason},
                                status_code=401, headers={"WWW-Authenticate": 'DPoP error="invalid_token"'})
    if VERIFY_MODE != "off":'''),
("Dockerfile", "COPY app.py .\n", "COPY app.py viewmac.py ./\n"),
],
"express": [
("app.js", "const fs = require('fs')\n", "const fs = require('fs')\nconst viewmac = require('./viewmac') // defence D-B (binding/harness/defence/express/viewmac.js)\n"),
("app.js", "if (!['off', 'origin-raw', 'origin-routed'].includes(VERIFY_MODE)) { console.error('bad VERIFY_MODE'); process.exit(2) }\n",
 """if (!['off', 'origin-raw', 'origin-routed'].includes(VERIFY_MODE)) { console.error('bad VERIFY_MODE'); process.exit(2) }
const DEFENCE = (process.env.DEFENCE || 'off').toLowerCase()
const VIEW_MAC_KEY = Buffer.from(process.env.VIEW_MAC_KEY || '', 'utf8')
if (!['off', 'db'].includes(DEFENCE)) { console.error('bad DEFENCE'); process.exit(2) }
if (DEFENCE === 'db' && !VIEW_MAC_KEY.length) { console.error('DEFENCE=db requires VIEW_MAC_KEY'); process.exit(2) }
"""),
("app.js", """  Object.assign(req.bh, { op_id: opId, route_template: template, path_params: params })
  if (VERIFY_MODE !== 'off') {""", """  Object.assign(req.bh, { op_id: opId, route_template: template, path_params: params })
  if (DEFENCE === 'db') { // D-B: X-Verified-View must match the view this executor dispatched on
    const r = viewmac.check(VIEW_MAC_KEY, viewmac.rawValues(req, viewmac.HEADER), viewmac.rawValues(req, 'dpop'), req.method, template, params)
    if (!r.ok) {
      req.bh.denied = true
      res.set('WWW-Authenticate', 'DPoP error="invalid_token"')
      return res.status(401).json({ op_id: opId, framework: FRAMEWORK, denied: true, reason: r.reason })
    }
  }
  if (VERIFY_MODE !== 'off') {"""),
("Dockerfile", "COPY app.js .\n", "COPY app.js viewmac.js ./\n"),
],
"spring": [
("src/main/java/bench/Bench.java", '''    public static final String LOG_FILE = env("LOG_FILE", "/logs/executor.jsonl");
''', '''    public static final String LOG_FILE = env("LOG_FILE", "/logs/executor.jsonl");
    /** Defence D-B (binding/harness/defence/spring): DEFENCE=off|db, key from VIEW_MAC_KEY. */
    public static final String DEFENCE = env("DEFENCE", "off");
    static final bench.defence.ViewMac VIEW_MAC = "db".equals(DEFENCE)
            ? new bench.defence.ViewMac(env("VIEW_MAC_KEY", "").getBytes(StandardCharsets.UTF_8)) : null;
    public static final String A_DEFENCE_REASON = "bench.defence_reason";
'''),
("src/main/java/bench/Bench.java", '''        req.setAttribute(A_PARAMS, params);
        if ("off".equals(VERIFY_MODE)) return true;''', '''        req.setAttribute(A_PARAMS, params);
        if (VIEW_MAC != null) {   // D-B: X-Verified-View must match the view this executor dispatched on
            bench.defence.ViewMac.Result r = VIEW_MAC.check(Collections.list(req.getHeaders("X-Verified-View")),
                    Collections.list(req.getHeaders("DPoP")), req.getMethod(), template, params);
            if (!r.ok()) {
                req.setAttribute(A_DENIED, Boolean.TRUE);
                req.setAttribute(A_DEFENCE_REASON, r.reason());
                return false;
            }
        }
        if ("off".equals(VERIFY_MODE)) return true;'''),
("src/main/java/bench/Bench.java", '''    public static Map<String, Object> deniedBody(String opId) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("op_id", opId);
        m.put("framework", FRAMEWORK);
        m.put("denied", true);''', '''    public static Map<String, Object> deniedBody(String opId) {
        return deniedBody(opId, null);
    }

    public static Map<String, Object> deniedBody(String opId, Object reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("op_id", opId);
        m.put("framework", FRAMEWORK);
        m.put("denied", true);
        if (reason != null) m.put("reason", reason);'''),
("src/main/java/bench/V1Controller.java", '''            return ResponseEntity.status(401).body(Bench.deniedBody(opId));''',
'''            Object reason = req.getAttribute(Bench.A_DEFENCE_REASON);
            return reason == null ? ResponseEntity.status(401).body(Bench.deniedBody(opId))
                    : ResponseEntity.status(401).header("WWW-Authenticate", "DPoP error=\\"invalid_token\\"")
                        .body(Bench.deniedBody(opId, reason));'''),
("src/main/java/bench/App.java", '''    public static void main(String[] args) {
''', '''    public static void main(String[] args) {
        String defence = System.getenv().getOrDefault("DEFENCE", "off");
        if (!"off".equals(defence) && !"db".equals(defence)) { System.err.println("bad DEFENCE"); System.exit(2); }
        if ("db".equals(defence) && System.getenv().getOrDefault("VIEW_MAC_KEY", "").isEmpty()) {
            System.err.println("DEFENCE=db requires VIEW_MAC_KEY"); System.exit(2);
        }
'''),
],
"aspnet": [
("Program.cs", '''var overrideOn = Env("OVERRIDE", "off") == "on";
''', '''var overrideOn = Env("OVERRIDE", "off") == "on";
// Defence D-B (binding/harness/defence/aspnet/ViewMac): DEFENCE=off|db, key from VIEW_MAC_KEY.
var defence = Env("DEFENCE", "off");
if (defence != "off" && defence != "db") { Console.Error.WriteLine("bad DEFENCE"); Environment.Exit(2); }
var viewMac = defence == "db" ? new Bench.Defence.ViewMac(Encoding.UTF8.GetBytes(Env("VIEW_MAC_KEY", ""))) : null;
'''),
("Program.cs", '''    ctx.Items["path_params"] = pathParams;
    if (verifyMode != "off")''', '''    ctx.Items["path_params"] = pathParams;
    if (viewMac is not null) // D-B: X-Verified-View must match the view this executor dispatched on
    {
        var r = viewMac.Check(ctx.Request.Headers["X-Verified-View"].Select(v => v ?? "").ToList(),
                              ctx.Request.Headers["DPoP"].Select(v => v ?? "").ToList(), ctx.Request.Method, template, pathParams);
        if (!r.Ok)
        {
            ctx.Items["denied"] = true;
            ctx.Response.Headers.WWWAuthenticate = "DPoP error=\\"invalid_token\\"";
            return Results.Json(new Dictionary<string, object?> { ["op_id"] = opId, ["framework"] = framework, ["denied"] = true, ["reason"] = r.Reason }, jsonOpts, statusCode: 401);
        }
    }
    if (verifyMode != "off")'''),
("Dockerfile", "COPY Program.cs .\n", "COPY Program.cs ViewMac.cs ./\n"),
],
}


def main():
    with tempfile.TemporaryDirectory() as t:
        t = pathlib.Path(t)
        for fw in EDITS:
            for side in ("a", "b"):
                shutil.copytree(H / "executors" / fw, t / side / "executors" / fw, ignore=IGNORE)
            b = t / "b" / "executors" / fw
            for src, dst in MODULES[fw]:
                (b / dst).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, b / dst)
            for rel, old, new in EDITS[fw]:
                p = b / rel
                s = p.read_text(encoding="utf-8")
                if s.count(old) != 1:
                    raise SystemExit(f"{fw}/{rel}: anchor found {s.count(old)} times (executor drifted?): {old[:60]!r}")
                p.write_text(s.replace(old, new), encoding="utf-8")
            r = subprocess.run(["diff", "-ruN", f"a/executors/{fw}", f"b/executors/{fw}"], cwd=t, capture_output=True, text=True)
            if r.returncode not in (0, 1):
                raise SystemExit(r.stderr)
            (D / "patches" / f"{fw}-defence-db.patch").write_text(r.stdout, encoding="utf-8")
            print(f"wrote defence/patches/{fw}-defence-db.patch")


if __name__ == "__main__":
    main()
