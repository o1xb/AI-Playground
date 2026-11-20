import sys,json,glob,os
from collections import Counter,defaultdict
key,run=sys.argv[1],sys.argv[2]
T={d["line"]:d for d in map(json.loads,open(key))}
P={}
for f in glob.glob(run+"/out/groups/*.jsonl"):
    for l in open(f):
        d=json.loads(l); P[d["offset"]+1]=d["label"]
rp=run+"/state/residual.jsonl"
if os.path.exists(rp):
    for l in open(rp): P[json.loads(l)["offset"]+1]="__residual__"
g2t=defaultdict(Counter)
for l,t in T.items(): g2t[P.get(l,"MISSING")][t["vendor"]]+=1
gmap={g:c.most_common(1)[0][0] for g,c in g2t.items()}
for name,sel in (("held-out lines, known vendors",True),("new vendors",False)):
    ls=[l for l,t in T.items() if t["seen_vendor"]==sel]
    res=sum(P[l]=="__residual__" for l in ls); cl=[l for l in ls if P[l]!="__residual__"]
    ok=sum(gmap[P[l]]==T[l]["vendor"] for l in cl)
    print(f"{name:32s} lines={len(ls):5d} fast-path={len(cl):5d} ({len(cl)/len(ls):.1%}) residual={res:5d} | correct among classified={ok}/{len(cl)} ({ok/max(1,len(cl)):.1%})")
bad=Counter((T[l]["vendor"],P[l]) for l in T if P[l]!="__residual__" and gmap[P[l]]!=T[l]["vendor"])
if bad: print("misroutes (truth, predicted):",bad.most_common(12))
