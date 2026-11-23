import sys,urllib.request,urllib.parse,json,time
qs=json.load(open(sys.argv[1])); out={}
for name,q in qs.items():
    url='https://api.crossref.org/works?'+urllib.parse.urlencode({'query.bibliographic':q,'rows':40,'filter':'from-pub-date:2016-01-01','select':'DOI,title,author,container-title,issued,type'})
    d=json.load(urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'lit-review-script'}),timeout=60))['message']
    out[name]={'query':q,'total':d['total-results'],'items':d['items']}; print(name,d['total-results'],file=sys.stderr); time.sleep(1)
json.dump(out,open(sys.argv[2],'w'),indent=1)
