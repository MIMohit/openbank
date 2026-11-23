import sys,subprocess,re
pdf=sys.argv[1]; pats=sys.argv[2:]
n=int(re.search(r'Pages:\s+(\d+)',subprocess.run(['pdfinfo',pdf],capture_output=True,text=True).stdout).group(1))
for p in range(1,n+1):
    t=subprocess.run(['pdftotext','-f',str(p),'-l',str(p),pdf,'-'],capture_output=True,text=True).stdout
    for pat in pats:
        for m in re.finditer(pat,t,re.I):
            s=t[max(0,m.start()-120):m.end()+160].replace('\n',' ')
            print(f"p{p} [{pat}] ...{s}...")
