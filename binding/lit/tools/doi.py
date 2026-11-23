import sys,json,urllib.request,urllib.parse,time
out={}
for doi in sys.argv[2:]:
    try:
        m=json.load(urllib.request.urlopen(urllib.request.Request('https://api.crossref.org/works/'+urllib.parse.quote(doi),headers={'User-Agent':'lit-review-script'}),timeout=30))['message']
        out[doi]={'title':(m.get('title') or [''])[0],'authors':[f"{a.get('given','')} {a.get('family','')}".strip() for a in m.get('author',[])],
          'container':(m.get('container-title') or [''])[0],'year':m.get('issued',{}).get('date-parts',[[None]])[0][0],'pages':m.get('page'),'publisher':m.get('publisher'),'type':m.get('type')}
    except Exception as e: out[doi]={'error':str(e)}
    print(doi, json.dumps(out[doi])[:330]); time.sleep(0.5)
json.dump(out,open(sys.argv[1],'w'),indent=1)
