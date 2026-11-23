"""arXiv export API query, restricted to submissions >= 2026-01-01. usage: python3 -I arxiv_q.py '<search_query>'"""
import sys, urllib.parse, urllib.request, re, json, datetime, pathlib, xml.etree.ElementTree as ET
q = sys.argv[1]
url = "http://export.arxiv.org/api/query?" + urllib.parse.urlencode({"search_query": q, "start": 0, "max_results": 100, "sortBy": "submittedDate", "sortOrder": "descending"})
x = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "lit-review-script"}), timeout=60).read()
ns = {"a": "http://www.w3.org/2005/Atom"}
rows = []
for e in ET.fromstring(x).findall("a:entry", ns):
    pub = e.find("a:published", ns).text[:10]
    if pub < "2026-01-01": continue
    rows.append({"id": e.find("a:id", ns).text, "published": pub, "title": re.sub(r"\s+", " ", e.find("a:title", ns).text).strip(),
                 "cats": [c.get("term") for c in e.findall("a:category", ns)]})
log = pathlib.Path(__file__).resolve().parent.parent / "search_log" / "arxiv2026.jsonl"
with log.open("a") as f: f.write(json.dumps({"ts": datetime.datetime.now().isoformat(), "query": q, "n_2026": len(rows), "rows": rows}) + "\n")
print(f"# {q} n_2026={len(rows)}")
for r in rows: print(r["published"], r["id"].split("/abs/")[-1], "|", r["title"], "|", ",".join(r["cats"][:3]))
