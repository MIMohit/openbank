import sys,urllib.request,urllib.parse,xml.etree.ElementTree as ET,json,time
qs=json.load(open(sys.argv[1])); out={}
ns={'a':'http://www.w3.org/2005/Atom'}
for name,q in qs.items():
    url='http://export.arxiv.org/api/query?'+urllib.parse.urlencode({'search_query':q,'max_results':100,'sortBy':'submittedDate'})
    x=urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'lit-review'}),timeout=60).read()
    r=ET.fromstring(x); tot=r.find('{http://a9.com/-/spec/opensearch/1.1/}totalResults').text
    items=[]
    for e in r.findall('a:entry',ns):
        items.append({'id':e.find('a:id',ns).text.split('/abs/')[-1],'title':' '.join(e.find('a:title',ns).text.split()),
          'authors':'; '.join(a.find('a:name',ns).text for a in e.findall('a:author',ns)),'published':e.find('a:published',ns).text[:10],
          'summary':' '.join(e.find('a:summary',ns).text.split())})
    out[name]={'query':q,'total':tot,'items':items}; print(name,tot,len(items),file=sys.stderr); time.sleep(3)
json.dump(out,open(sys.argv[2],'w'),indent=1)
