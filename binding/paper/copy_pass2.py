"""Copy the pass-2 entries cited by the paper from ../lit/pass2/refs_pass2.bib into extra.bib,
stripping the reviewer evidence notes (FT/ABS/UNVERIFIED) so they do not print. Keys are kept.
Run from binding/paper after a build:  python3 copy_pass2.py   (W25)"""
import re, pathlib
aux = pathlib.Path("build/main.aux").read_text()
cited = set()
for m in re.finditer(r"\\citation\{([^}]*)\}", aux):
    cited |= {k.strip() for k in m.group(1).split(",")}
src = pathlib.Path("../lit/pass2/refs_pass2.bib").read_text()
entries = re.split(r"\n(?=@)", src)
out = []
for e in entries:
    m = re.match(r"@\w+\{([^,]+),", e.strip())
    if not m or m.group(1) not in cited:
        continue
    e = e.strip()
    note = re.search(r"\n\s*note\s*=\s*\{(.*)\}\s*\n\}\s*$", e, re.S)
    if note:
        urls = re.findall(r"\\url\{([^}]+)\}|(https?://[^\s)]+)", note.group(1))
        e = e[:note.start()] + "\n}"
        e = re.sub(r",\s*\n\}$", "\n}", e)
        if "url" not in re.findall(r"\n\s*(\w+)\s*=", e) and urls:
            u = urls[0][0] or urls[0][1]
            e = e[:-2] + f",\n  url          = {{{u}}}\n}}"
    e = e.replace("{{xvnpw (Marcin Niemiec)}}", "{{xvnpw}}")
    out.append(e)
p = pathlib.Path("extra.bib"); s = p.read_text()
marker = "% ==== pass-2 entries copied by copy_pass2.py (notes stripped) ===="
s = s.split(marker)[0].rstrip() + "\n\n" + marker + "\n" + "\n\n".join(out) + "\n"
p.write_text(s)
print(len(out), "entries copied")
