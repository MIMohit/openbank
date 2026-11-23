#!/bin/sh
# Fetch inputs for the E1 named-spec analysis (FHIR, MCP) and the APIs.guru corpus.
# Run from binding/prevalence/.  All downloads land in data/ (gitignored).
set -eu
mkdir -p data/named
[ -d data/openapi-directory ] || git clone --depth 1 https://github.com/APIs-guru/openapi-directory.git data/openapi-directory
curl -sfL https://api.apis.guru/v2/list.json -o data/apisguru_list.json
cd data/named
for v in R4 R5; do curl -sfL "https://hl7.org/fhir/$v/http.html" -o "fhir_$(echo $v | tr R r)_http.html"; done
curl -sfL https://hl7.org/fhir/R5/operations.html -o fhir_r5_operations.html
for f in fhir_r4_http fhir_r5_http fhir_r5_operations; do
  python3 -I -c "
import re,html
t=open('$f.html',encoding='utf-8',errors='replace').read()
t=re.sub(r'<script.*?</script>|<style.*?</style>','',t,flags=re.S)
t=html.unescape(re.sub(r'<[^>]+>',' ',t)); t=re.sub(r'[ \t]+',' ',t)
open('$f.txt','w').write(t)"
done
date -u +%FT%TZ > hapi_r4_metadata.fetched_at
curl -sfL -H 'Accept: application/fhir+json' https://hapi.fhir.org/baseR4/metadata -o hapi_r4_metadata.json
# MCP specification, pinned to a commit of modelcontextprotocol/modelcontextprotocol
S=${MCP_SHA:-862397cec702e8f828713071da501cf56158e8fc}
echo "$S" > mcp_main_sha.txt
B=https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/$S/docs/specification
curl -sfL $B/2026-07-28/basic/transports/streamable-http.mdx -o mcp_2026-07-28_streamable-http.mdx
curl -sfL $B/2025-11-25/basic/transports.mdx -o mcp_2025-11-25_transports.mdx
curl -sfL $B/2026-07-28/basic/authorization/index.mdx -o mcp_2026-07-28_auth_index.mdx
curl -sfL $B/2025-11-25/basic/authorization.mdx -o mcp_2025-11-25_authorization.mdx
