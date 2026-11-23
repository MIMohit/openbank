"""Apply W11's D-B edits (harness/defence/patches/make_patches.py EDITS/MODULES, imported unchanged)
to fresh copies of the CURRENT executor sources (which include W15's ROUTES=v2 code) under
build/src/executors/<fw>, and write the regenerated diffs to build/patches/<fw>-defence-db.v2.patch.
The shipped W11 patches predate W15's v2 routes; aspnet's no longer applies with `patch` (context drift),
while every EDITS anchor still matches exactly once. Never touches harness/."""
import importlib.util, pathlib, shutil, subprocess, sys
HERE = pathlib.Path(__file__).resolve().parents[1]
H = HERE.parents[1] / "harness"
spec = importlib.util.spec_from_file_location("mp", H / "defence/patches/make_patches.py")
mp = importlib.util.module_from_spec(spec); spec.loader.exec_module(mp)
SRC = HERE / "build/src"; PAT = HERE / "build/patches"; PAT.mkdir(parents=True, exist_ok=True)
for fw in sys.argv[1:] or mp.EDITS:
    a = SRC / "a" / "executors" / fw; b = SRC / "executors" / fw
    for d in (a, b):
        shutil.rmtree(d, ignore_errors=True); shutil.copytree(H / "executors" / fw, d, ignore=mp.IGNORE)
    for src, dst in mp.MODULES[fw]:
        (b / dst).parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(src, b / dst)
    for rel, old, new in mp.EDITS[fw]:
        p = b / rel; s = p.read_text()
        assert s.count(old) == 1, (fw, rel, old[:60]); p.write_text(s.replace(old, new))
    r = subprocess.run(["diff", "-ruN", f"a/executors/{fw}", f"executors/{fw}"], cwd=SRC, capture_output=True, text=True)
    (PAT / f"{fw}-defence-db.v2.patch").write_text(r.stdout); print(fw, "ok", len(r.stdout.splitlines()), "diff lines")
