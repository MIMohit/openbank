import sys,urllib.request,urllib.parse,json,time
qs=json.load(open(sys.argv[1])); out={}
for name,q in qs.items():
    url='https://api.semanticscholar.org/graph/v1/paper/search?'+urllib.parse.urlencode({'query':q,'limit':50,'fields':'title,authors,venue,year,externalIds,url','year':'2016-2026'})
    for t in range(4):
        try:
            d=json.load(urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'lit-review'}),timeout=60)); break
        except Exception as e:
            print(name,'retry',e,file=sys.stderr); time.sleep(8)
    else: d={'total':'ERR','data':[]}
    out[name]={'query':q,'total':d.get('total'),'items':d.get('data',[])}; print(name,d.get('total'),file=sys.stderr); time.sleep(4)
json.dump(out,open(sys.argv[2],'w'),indent=1)
