"""Fetch each URL (GET, follow redirects) and record status + <title>; DOIs resolved via Crossref API.
usage: python3 -I verify_urls.py urls.txt > search_log/url_verification.tsv"""
import sys, re, json, urllib.request, html
def get(u):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (lit-review)"}), timeout=40)
        b = r.read(400000).decode("utf-8", "replace"); m = re.search(r"<title[^>]*>(.*?)</title>", b, re.S | re.I)
        return r.status, html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:120] if m else ("pdf/no-title" if b.startswith("%PDF") else "")
    except Exception as e:
        return getattr(e, "code", "ERR"), str(e)[:80]
print("key\tkind\ttarget\tstatus\ttitle_or_crossref_title")
for line in open(sys.argv[1]):
    line = line.strip()
    if not line or line.startswith("#"): continue
    key, tgt = line.split(None, 1)
    if tgt.startswith("10."):
        try:
            d = json.load(urllib.request.urlopen(f"https://api.crossref.org/works/{tgt}", timeout=40))["message"]
            print(f"{key}\tdoi\t{tgt}\t200\t{d.get('title',[''])[0][:110]} | {d.get('container-title',[''])[0][:60] if d.get('container-title') else ''} | {d.get('issued',{}).get('date-parts',[[None]])[0][0]}")
        except Exception as e:
            print(f"{key}\tdoi\t{tgt}\t{getattr(e,'code','ERR')}\t{str(e)[:80]}")
    else:
        s, t = get(tgt); print(f"{key}\turl\t{tgt}\t{s}\t{t}")
    sys.stdout.flush()
