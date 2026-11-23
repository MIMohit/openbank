"""W23: build bh-exec-<fw>:pathmap from a patched COPY of the current executor source.

Base = W11's D-B integration (harness/defence/patches/make_patches.py MODULES+EDITS, imported
unchanged, which also copies in the W23-updated viewmac that carries the path-map functions).
Then W23 PATHMAP_EDITS wire DEFENCE_PATH_MAP / DEFENCE_WILDCARDS into the D-B call site and the
D-A (origin-routed) view, so BOTH the verifier-side canonical view and the executor-side recomputed
view are expressed in PUBLIC-path space. Never touches harness/executors/ or harness/orchestrator/.
New image tag :pathmap only; :latest, :v2, :defence are never overwritten.

Usage (from binding/harness):  python3 ../experiments/gaps/pathmap/build_pathmap.py fastapi express [...]
"""
import importlib.util, json, pathlib, shutil, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent          # experiments/gaps/pathmap
H = HERE.parents[2] / "harness"                          # binding/harness
spec = importlib.util.spec_from_file_location("mp", H / "defence/patches/make_patches.py")
mp = importlib.util.module_from_spec(spec); spec.loader.exec_module(mp)

SRC = HERE / "build" / "src"
# DEFENCE is NOT baked: it is derived from VERIFY_MODE (which the orchestrator DOES set) so one image
# serves both roles -- edge (VERIFY_MODE=off -> D-B view MAC) and origin (VERIFY_MODE=origin-routed ->
# D-A, no D-B). See PATHMAP_EDITS. The map, key, wildcards and v2 routes are baked.
DOCKER_ENV = ("ROUTES=v2 VIEW_MAC_KEY=bh-test-view-mac-key "
              "DEFENCE_PATH_MAP=/pathmap.json DEFENCE_WILDCARDS=path")

# Extra edits applied AFTER the base D-B EDITS. Each (relpath, old, new); old must occur exactly once.
PATHMAP_EDITS = {
"fastapi": [
 # 0. derive DEFENCE from VERIFY_MODE: edge (off) -> D-B view MAC; origin-routed -> D-A only.
 ('app.py',
  'DEFENCE = os.environ.get("DEFENCE", "off").lower()',
  'DEFENCE = os.environ.get("DEFENCE", "db" if VERIFY_MODE == "off" else "off").lower()'),
 # 1. read the map env right after the DEFENCE/VIEW_MAC_KEY block
 ('app.py',
  'if DEFENCE == "db" and not VIEW_MAC_KEY:\n    sys.exit("DEFENCE=db requires VIEW_MAC_KEY")\n',
  'if DEFENCE == "db" and not VIEW_MAC_KEY:\n    sys.exit("DEFENCE=db requires VIEW_MAC_KEY")\n'
  'DEFENCE_PATH_MAP = os.environ.get("DEFENCE_PATH_MAP", "")\n'
  'DEFENCE_WILDCARDS = frozenset(w for w in os.environ.get("DEFENCE_WILDCARDS", "path").split(",") if w)\n'
  'def _pathmap_rules():\n'
  '    return viewmac.load_rules(DEFENCE_PATH_MAP) if DEFENCE_PATH_MAP else None\n'),
 # 2. D-B call site: pass the map + wildcards
 ('app.py',
  '[v for k, v in bh["headers"] if k == "dpop"], method, template, params)',
  '[v for k, v in bh["headers"] if k == "dpop"], method, template, params,\n'
  '                            pathmap=_pathmap_rules(), wildcards=DEFENCE_WILDCARDS)'),
 # 3. D-A origin-routed: express the matched route in public-path space
 ('app.py',
  '        else:\n            vm, vu = method, canonical_path(template, params)\n',
  '        else:\n'
  '            _rules = _pathmap_rules()\n'
  '            if _rules is None:\n'
  '                vm, vu = method, canonical_path(template, params)\n'
  '            else:\n'
  '                vm, vu = method, viewmac.to_public(viewmac.substitute_pm(template, params, DEFENCE_WILDCARDS), _rules)\n'),
],
"express": [
 ('app.js',
  "const DEFENCE = (process.env.DEFENCE || 'off').toLowerCase()",
  "const DEFENCE = (process.env.DEFENCE || (VERIFY_MODE === 'off' ? 'db' : 'off')).toLowerCase()"),
 ('app.js',
  "if (DEFENCE === 'db' && !VIEW_MAC_KEY.length) { console.error('DEFENCE=db requires VIEW_MAC_KEY'); process.exit(2) }\n",
  "if (DEFENCE === 'db' && !VIEW_MAC_KEY.length) { console.error('DEFENCE=db requires VIEW_MAC_KEY'); process.exit(2) }\n"
  "const DEFENCE_PATH_MAP = process.env.DEFENCE_PATH_MAP || ''\n"
  "const DEFENCE_WILDCARDS = new Set((process.env.DEFENCE_WILDCARDS || 'path').split(',').filter(Boolean))\n"
  "function pathmapRules () { return DEFENCE_PATH_MAP ? viewmac.loadRules(DEFENCE_PATH_MAP) : null }\n"),
 ('app.js',
  "viewmac.rawValues(req, 'dpop'), req.method, template, params)",
  "viewmac.rawValues(req, 'dpop'), req.method, template, params, pathmapRules(), DEFENCE_WILDCARDS)"),
 ('app.js',
  "    const [vm, vu] = VERIFY_MODE === 'origin-raw'\n"
  "      ? [req.bh.rawMethod, req.bh.rawTarget]\n"
  "      : [req.method, canonicalPath(template, params)]\n",
  "    let vm, vu\n"
  "    if (VERIFY_MODE === 'origin-raw') { vm = req.bh.rawMethod; vu = req.bh.rawTarget } else {\n"
  "      const _r = pathmapRules(); vm = req.method\n"
  "      vu = _r === null ? canonicalPath(template, params) : viewmac.toPublic(viewmac.substitutePm(template, params, DEFENCE_WILDCARDS), _r)\n"
  "    }\n"),
],
"spring": [
 # 0. DEFENCE from VERIFY_MODE
 ('src/main/java/bench/Bench.java',
  'public static final String DEFENCE = env("DEFENCE", "off");',
  'public static final String DEFENCE = env("DEFENCE", "off".equals(VERIFY_MODE) ? "db" : "off");'),
 # 1. map env + helper, right after the VIEW_MAC field
 ('src/main/java/bench/Bench.java',
  '    public static final String A_DEFENCE_REASON = "bench.defence_reason";\n',
  '    public static final String A_DEFENCE_REASON = "bench.defence_reason";\n'
  '    public static final String DEFENCE_PATH_MAP = env("DEFENCE_PATH_MAP", "");\n'
  '    public static final java.util.Set<String> DEFENCE_WILDCARDS = new java.util.HashSet<>(java.util.Arrays.asList(env("DEFENCE_WILDCARDS", "path").split(",")));\n'
  '    static java.util.List<String[]> pathmapRules() { return DEFENCE_PATH_MAP.isEmpty() ? null : bench.defence.ViewMac.loadRules(DEFENCE_PATH_MAP); }\n'),
 # 2. D-B call site
 ('src/main/java/bench/Bench.java',
  'Collections.list(req.getHeaders("DPoP")), req.getMethod(), template, params);',
  'Collections.list(req.getHeaders("DPoP")), req.getMethod(), template, params, pathmapRules(), DEFENCE_WILDCARDS);'),
 # 3. D-A origin-routed
 ('src/main/java/bench/Bench.java',
  '            uri = substitute(template, params);\n',
  '            java.util.List<String[]> _r = pathmapRules();\n'
  '            uri = _r == null ? substitute(template, params) : bench.defence.ViewMac.toPublic(bench.defence.ViewMac.substitutePm(template, params, DEFENCE_WILDCARDS), _r);\n'),
],
"aspnet": [
 # 0. DEFENCE from verifyMode
 ('Program.cs', 'var defence = Env("DEFENCE", "off");',
  'var defence = Env("DEFENCE", verifyMode == "off" ? "db" : "off");'),
 # 1. map env + helper, right after the viewMac line
 ('Program.cs',
  'var viewMac = defence == "db" ? new Bench.Defence.ViewMac(Encoding.UTF8.GetBytes(Env("VIEW_MAC_KEY", ""))) : null;\n',
  'var viewMac = defence == "db" ? new Bench.Defence.ViewMac(Encoding.UTF8.GetBytes(Env("VIEW_MAC_KEY", ""))) : null;\n'
  'var defencePathMap = Env("DEFENCE_PATH_MAP", "");\n'
  'var defenceWildcards = (ISet<string>)new HashSet<string>(Env("DEFENCE_WILDCARDS", "path").Split(\',\', StringSplitOptions.RemoveEmptyEntries));\n'
  'Func<List<(string, string)>?> pathmapRules = () => defencePathMap.Length > 0 ? Bench.Defence.ViewMac.LoadRules(defencePathMap) : null;\n'),
 # 2. D-B call site
 ('Program.cs',
  'ctx.Request.Headers["DPoP"].Select(v => v ?? "").ToList(), ctx.Request.Method, template, pathParams);',
  'ctx.Request.Headers["DPoP"].Select(v => v ?? "").ToList(), ctx.Request.Method, template, pathParams, pathmapRules(), defenceWildcards);'),
 # 3. D-A origin-routed
 ('Program.cs',
  '            uri = template;\n            foreach (var kv in pathParams) uri = uri.Replace("{" + kv.Key + "}", EncSegment(kv.Value));\n',
  '            var _r = pathmapRules();\n'
  '            if (_r is null) { uri = template; foreach (var kv in pathParams) uri = uri.Replace("{" + kv.Key + "}", EncSegment(kv.Value)); }\n'
  '            else uri = Bench.Defence.ViewMac.ToPublic(Bench.Defence.ViewMac.SubstitutePm(template, pathParams, defenceWildcards), _r);\n'),
],
}


def build(fw):
    b = SRC / fw
    shutil.rmtree(b, ignore_errors=True)
    shutil.copytree(H / "executors" / fw, b, ignore=mp.IGNORE)
    for src, dst in mp.MODULES[fw]:                         # W23-updated viewmac module
        (b / dst).parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(src, b / dst)
    for rel, old, new in mp.EDITS[fw]:                      # base D-B wiring
        p = b / rel; s = p.read_text(); assert s.count(old) == 1, ("base", fw, rel, old[:50]); p.write_text(s.replace(old, new))
    for rel, old, new in PATHMAP_EDITS[fw]:                 # W23 path-map wiring
        p = b / rel; s = p.read_text(); assert s.count(old) == 1, ("pm", fw, rel, old[:50]); p.write_text(s.replace(old, new))
    (b / "pathmap.json").write_text(json.dumps({"rules": []}) + "\n")
    df = b / "Dockerfile"; d = df.read_text()
    df.write_text(d + f"\nCOPY pathmap.json /pathmap.json\nENV {DOCKER_ENV}\n")
    print(f"[{fw}] patched copy at {b}")
    r = subprocess.run(["docker", "build", "-t", f"bh-exec-{fw}:pathmap", str(b)],
                       capture_output=True, text=True)
    (HERE / "build" / f"build-{fw}.log").write_text(r.stdout + "\n--- STDERR ---\n" + r.stderr)
    if r.returncode != 0:
        print(f"[{fw}] BUILD FAILED (see build/build-{fw}.log):"); print(r.stderr[-1500:]); return False
    iid = subprocess.run(["docker", "image", "inspect", f"bh-exec-{fw}:pathmap", "--format", "{{.Id}}"],
                         capture_output=True, text=True).stdout.strip()
    print(f"[{fw}] built bh-exec-{fw}:pathmap {iid}")
    return True


if __name__ == "__main__":
    (SRC).mkdir(parents=True, exist_ok=True)
    ok = all(build(fw) for fw in (sys.argv[1:] or ["fastapi", "express", "spring", "aspnet"]))
    sys.exit(0 if ok else 1)
