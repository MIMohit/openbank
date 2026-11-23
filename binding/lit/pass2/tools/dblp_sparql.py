"""dblp title search via the public SPARQL endpoint (sparql.dblp.org).
The dblp search API and web UI return an anti-bot challenge to scripts (2026-11-24),
so this is the 'by hand' dblp channel. Each query = list of lower-case substrings that
must ALL appear in the title. Output: JSON lines appended to search_log/dblp.jsonl.
usage: python3 -I dblp_sparql.py "term1|term2" [min_year]
"""
import json, sys, urllib.parse, urllib.request, datetime, pathlib
terms = [t.strip().lower() for t in sys.argv[1].split('|') if t.strip()]
miny = int(sys.argv[2]) if len(sys.argv) > 2 else 2014
filt = " ".join(f'FILTER(CONTAINS(LCASE(STR(?t)), {json.dumps(t)}))' for t in terms)
q = f"""PREFIX dblp: <https://dblp.org/rdf/schema#>
SELECT ?p ?t ?y (SAMPLE(?v) AS ?venue) (SAMPLE(?d) AS ?doi) (GROUP_CONCAT(DISTINCT ?an; separator="; ") AS ?authors) WHERE {{
 ?p dblp:title ?t . {filt}
 ?p dblp:yearOfPublication ?y . FILTER(?y >= "{miny}"^^<http://www.w3.org/2001/XMLSchema#gYear>)
 OPTIONAL {{ ?p dblp:publishedIn ?v }} OPTIONAL {{ ?p dblp:doi ?d }}
 OPTIONAL {{ ?p dblp:authoredBy ?a . ?a dblp:primaryCreatorName ?an }}
}} GROUP BY ?p ?t ?y ORDER BY DESC(?y) LIMIT 200"""
url = "https://sparql.dblp.org/sparql?" + urllib.parse.urlencode({"query": q})
req = urllib.request.Request(url, headers={"Accept": "application/sparql-results+json", "User-Agent": "lit-review-script"})
res = json.load(urllib.request.urlopen(req, timeout=120))
rows = [{k: v["value"] for k, v in b.items()} for b in res["results"]["bindings"]]
log = pathlib.Path(__file__).resolve().parent.parent / "search_log" / "dblp.jsonl"
with log.open("a") as f:
    f.write(json.dumps({"ts": datetime.datetime.now().isoformat(), "query_terms": terms, "min_year": miny, "n": len(rows), "rows": rows}) + "\n")
print(f"# terms={terms} min_year={miny} n={len(rows)}")
for r in rows:
    print(r.get("y"), "|", r.get("t"), "|", r.get("venue", ""), "|", r.get("doi", r.get("p")))
