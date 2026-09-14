#!/usr/bin/env bash
# Preflight for the Phoenix Blue intelligence skills.
#
# Checks the host, the key, and every gate the skills depend on.
# Prints what works, what does not, and why.
#
# Usage:
#   export PHOENIX_API_KEY="phx_api_power_..."
#   export PHOENIX_API_URL="https://phxintel.security"
#   ./scripts/check_setup.sh

set -u

API_URL="${PHOENIX_API_URL:-https://phxintel.security}"
MCP_URL="${PHOENIX_MCP_URL:-${API_URL}/api/v1/mcp}"
KEY="${PHOENIX_API_KEY:-}"
TIMEOUT="${PHOENIX_TIMEOUT:-30}"

PASS=0
FAIL=0

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ OK ]   %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  [ FAIL ] %s\n' "$*"; FAIL=$((FAIL+1)); }
note() { printf '  [ note ] %s\n' "$*"; }

say ""
say "Phoenix Blue intelligence — preflight"
say "====================================="
say "  API URL : ${API_URL}"
say "  MCP URL : ${MCP_URL}"

# ---------------------------------------------------------------- 1. the key
say ""
say "1. API key"
if [ -z "${KEY}" ]; then
  bad "PHOENIX_API_KEY is not set. Export it and run again."
  say ""
  say "Result: 0 passed, 1 failed. Cannot continue without a key."
  exit 1
fi

PREFIX="$(printf '%s' "$KEY" | sed -E 's/^(phx_[a-z_]*_).*/\1/')"
ok "key present, prefix ${PREFIX}"

case "$PREFIX" in
  phx_api_power_|phx_api_int_|phx_api_unl_)
    ok "scope clears both MCP and the CRA upgrade surface" ;;
  phx_mcp_)
    note "MCP-only scope. The CRA upgrade endpoint will return 403." ;;
  phx_api_basic_)
    note "Registered tier. Both MCP and CRA will refuse this key." ;;
  phx_gintel_)
    note "Global Intel is a product licence, not an access scope."
    note "Expect 404 on MCP and 403 on CRA. Get a phx_api_power_ key." ;;
  *)
    note "Unrecognised prefix for these skills. See docs/API_KEYS.md." ;;
esac

# ------------------------------------------------------------ 2. host is up
say ""
say "2. Host reachability"
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "${API_URL}/" 2>/dev/null)
if [ "$CODE" = "000" ]; then
  bad "cannot reach ${API_URL} (network, DNS, or TLS)"
else
  ok "${API_URL} responded ${CODE}"
fi

# -------------------------------------------------------------------- 3. MCP
say ""
say "3. MCP surface"
BODY=$(curl -s --max-time "$TIMEOUT" -w '\n%{http_code}' -X POST "$MCP_URL" \
  -H 'Content-Type: application/json' -H "x-api-key: ${KEY}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null)
CODE="${BODY##*$'\n'}"
JSON="${BODY%$'\n'*}"

case "$CODE" in
  200)
    COUNT=$(PHX_JSON="$JSON" python3 -c \
      'import json,os; print(len((json.loads(os.environ["PHX_JSON"]).get("result") or {}).get("tools") or []))' \
      2>/dev/null) || COUNT="?"
    ok "MCP reachable, ${COUNT} tools visible"
    PHX_JSON="$JSON" python3 - <<'PY' 2>/dev/null
import json,os
names={t["name"] for t in (json.loads(os.environ["PHX_JSON"]).get("result") or {}).get("tools") or []}
groups={
 "firewall (enable_firewall_mcp_server)": {"phoenix_check_package","phoenix_check_lockfile",
   "phoenix_get_package_intel","phoenix_get_alternatives","phoenix_firewall_rules"},
 "intel query (enable_intel_query_surface)": {"intel_get","intel_search","intel_vocabularies"},
 "cve bundles (ENABLE_CVE_BUNDLES)": {"bundles_for_cve","get_bundle"},
 "advisory patches (ENABLE_ADV_FETCH)": {"get_advisory_patches"},
 "enterprise scoring (Enterprise tier)": {"calculate_custom_phoenix_score","explain_score_components"},
}
for label, want in groups.items():
    have = want & names
    state = "available" if have == want else ("partial" if have else "OFF")
    print(f"  [ note ] {label}: {state}")
PY
    ;;
  404)
    bad "MCP returned 404 — the key is VALID but lacks the MCP scope"
    note "This is deliberate. See docs/API_KEYS.md section 2." ;;
  401)
    bad "MCP returned 401 — key unknown to this host, or no key sent"
    note "Keys are per-environment. A dev key 401s in production." ;;
  *)
    bad "MCP returned ${CODE}" ;;
esac

# ------------------------------------------------- 4. CRA upgrade endpoint
say ""
say "4. CRA upgrade surface (safe_upgrade_version)"
BODY=$(curl -s --max-time "$TIMEOUT" -w '\n%{http_code}' -X POST \
  "${API_URL}/api/v1/intel/library-versions" \
  -H 'Content-Type: application/json' -H "X-API-Key: ${KEY}" \
  -d '{"purls":["pkg:npm/lodash@4.17.20"]}' 2>/dev/null)
CODE="${BODY##*$'\n'}"
JSON="${BODY%$'\n'*}"

case "$CODE" in
  200)
    ok "CRA reachable"
    PHX_JSON="$JSON" python3 - <<'PY' 2>/dev/null
import json,os
d=json.loads(os.environ["PHX_JSON"])
for c in d.get("components",[]):
    print(f"  [ note ] {c.get('purl')}: {c.get('cra_vulnerability_total')} CVEs, "
          f"upgrade -> {c.get('safe_upgrade_version')!r} "
          f"({c.get('cra_safe_upgrade_corroboration')})")
print(f"  [ note ] data as of {(d.get('as_of') or {}).get('library_intel')}")
PY
    ;;
  403)
    bad "CRA returned 403 — key scope is below Pro tier" ;;
  404)
    bad "CRA returned 404 — flag enable_cra_intel_surface is off on this instance"
    note "Ask your Phoenix operator to enable it. Do not flip it yourself." ;;
  401)
    bad "CRA returned 401 — key unknown to this host" ;;
  *)
    bad "CRA returned ${CODE}" ;;
esac

# ----------------------------------------------------------------- summary
say ""
say "====================================="
say "Result: ${PASS} passed, ${FAIL} failed."
if [ "$FAIL" -gt 0 ]; then
  say "Read docs/API_KEYS.md and docs/MCP_SETUP.md for the failing checks."
  exit 1
fi
say "Both skills are ready to use."
exit 0
