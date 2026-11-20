import sys,json,math
from collections import Counter,defaultdict
key,asg=sys.argv[1],sys.argv[2]
T={d["line"]:d for d in map(json.loads,open(key))}
P={d["line"]:d for d in map(json.loads,open(asg))}
print("lines truth/pred:",len(T),len(P))
g2t=defaultdict(Counter); t2g=defaultdict(Counter)
for l,t in T.items():
    g=P.get(l,{}).get("group","MISSING"); g2t[g][t["vendor"]]+=1; t2g[t["vendor"]][g]+=1
gmap={g:c.most_common(1)[0][0] for g,c in g2t.items()}   # predicted group -> dominant true vendor
ok=sum(1 for l,t in T.items() if gmap[P.get(l,{}).get("group","MISSING")]==t["vendor"])
print(f"accuracy (each predicted group mapped to its dominant vendor): {ok}/{len(T)} = {ok/len(T):.1%}")
fam=lambda v:v.split("_")[0]
okf=sum(1 for l,t in T.items() if fam(gmap[P.get(l,{}).get("group","MISSING")])==fam(t["vendor"]))
print(f"vendor-family accuracy: {okf}/{len(T)} = {okf/len(T):.1%}")
def H(c):
    n=sum(c.values()); return -sum(x/n*math.log(x/n) for x in c.values())
N=len(T); Ht=H(Counter(t["vendor"] for t in T.values())); Hg=H(Counter(P.get(l,{}).get("group","MISSING") for l in T))
Htg=sum(sum(c.values())/N*H(c) for c in g2t.values()); Hgt=sum(sum(c.values())/N*H(c) for c in t2g.values())
h=1-Htg/Ht; cpl=1-Hgt/Hg; print(f"homogeneity {h:.3f}  completeness {cpl:.3f}  V-measure {2*h*cpl/(h+cpl):.3f}")
print("\n-- by transport:")
for tr in ["raw","relay","filebeat","truncated"]:
    ls=[l for l,t in T.items() if t["transport"]==tr]
    print(f"  {tr:10s} {sum(gmap[P.get(l,{}).get('group','MISSING')]==T[l]['vendor'] for l in ls)}/{len(ls)}")
print("\n-- vendors split across groups or mis-grouped (true vendor: {pred group: n}):")
for v,c in sorted(t2g.items()):
    bad={g:n for g,n in c.items() if gmap[g]!=v}
    if bad or len(c)>1: print(f"  {v:28s} {dict(c.most_common())}")
print("\n-- vendors never the dominant member of any group (absorbed):",sorted(set(t2g)-set(gmap.values())))
print("\n-- confidence calibration:")
cc=defaultdict(lambda:[0,0])
for l,t in T.items():
    p=P.get(l,{}); cf=p.get("confidence","?"); cc[cf][1]+=1; cc[cf][0]+=gmap[p.get("group","MISSING")]==t["vendor"]
for k,(a,b) in cc.items(): print(f"  {k:7s} {a}/{b} = {a/b:.1%}")
