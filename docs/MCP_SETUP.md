# Connecting Claude Code to the Phoenix MCP server

The Phoenix MCP server speaks JSON-RPC over HTTP at `POST /api/v1/mcp`. Claude
Code speaks MCP over stdio. `scripts/phoenix_mcp_bridge.py` sits between them.

---

## 1. Requirements

- Python 3.8 or newer. The bridge uses only the standard library.
- A Phoenix API key with an MCP-accepting scope. See
  [API_KEYS.md](API_KEYS.md) — `phx_api_power_`, `phx_api_int_`,
  `phx_api_unl_`, or `phx_mcp_`.
- Network access to your Phoenix instance.

---

## 2. Pick your endpoint

| Environment | `PHOENIX_MCP_URL` |
|---|---|
| Production | `https://phxintel.security/api/v1/mcp` |
| Local dev, through nginx | `http://localhost:3000/api/v1/mcp` |
| Local dev, backend direct | `http://localhost:8000/api/v1/mcp` |

The nginx config proxies `/api/` to the backend, so port 3000 and port 8000
reach the same handler.

There is also a `/api/v1/mcp/claude` alias. Both paths work.

**Keys are per-environment.** A key issued on a development instance returns
`401 {"detail":"Invalid or expired API key"}` in production, and the reverse.

---

## 3. Set the environment variables

```bash
export PHOENIX_API_KEY="phx_api_power_your_key_here"
export PHOENIX_MCP_URL="https://phxintel.security/api/v1/mcp"
```

Put these in your shell profile or your secret manager. Do not put them in a
file you commit.

---

## 4. Verify before you wire anything up

Run the preflight script. It checks the host, the key, and every gate the
skills depend on.

```bash
./scripts/check_setup.sh
```

Or do it by hand with one call:

```bash
curl -s -X POST "$PHOENIX_MCP_URL" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $PHOENIX_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

A working key returns a `result.tools` array. On a fully enabled Enterprise key
that array holds 27 tools.

If it does not work, read the response code against
[API_KEYS.md section 2](API_KEYS.md#the-404-trap-on-mcp). A `404` there means
your key is valid but carries the wrong scope. It does not mean the server is
missing.

---

## 5. Register the server with Claude Code

Copy the example and fill it in.

```bash
cp examples/mcp-manual-setup.json .mcp.json   # manual route only
```

`.mcp.json`:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "python3",
      "args": ["${CLAUDE_PROJECT_DIR}/scripts/phoenix_mcp_bridge.py"],
      "env": {
        "MCP_HTTP_URL": "${PHOENIX_MCP_URL}",
        "MCP_API_KEY": "${PHOENIX_API_KEY}"
      }
    }
  }
}
```

The key is read from your environment at launch. It is never written to the
file.

The two shapes differ: a **project** `.mcp.json` wraps servers in
`mcpServers`, a **plugin** `.mcp.json` does not. This repository's own
`.mcp.json` is the plugin form — do not overwrite it.

Restart Claude Code. The tools appear as `mcp__phoenix__<tool_name>`.

---

## 6. Bridge environment variables

| Variable | Default | Meaning |
|---|---|---|
| `MCP_HTTP_URL` | `http://localhost:8000/api/v1/mcp/claude` | Full endpoint URL |
| `MCP_API_KEY` | *(empty)* | Sent as the `x-api-key` header |
| `MCP_HTTP_TIMEOUT` | `30` | Request timeout, in seconds |
| `MCP_HTTP_INSECURE` | `0` | `1` disables TLS verification. Self-hosted only. |

Raise `MCP_HTTP_TIMEOUT` to `60` if you call `phoenix_check_lockfile` with
large lockfiles.

---

## 7. Feature flags can hide tools

The tool list is not fixed. It is built per caller from the tier, the key scope,
and the server's feature flags. A tool that is absent is not broken — it is
switched off or above your tier.

| Missing tools | Flag or gate |
|---|---|
| `phoenix_check_package`, `phoenix_check_lockfile`, `phoenix_get_package_intel`, `phoenix_get_alternatives`, `phoenix_firewall_rules` | `enable_firewall_mcp_server` |
| `intel_get`, `intel_search`, `intel_vocabularies` | `enable_intel_query_surface` |
| `bundles_for_cve`, `get_bundle` | `ENABLE_CVE_BUNDLES` |
| `get_advisory_patches` | `ENABLE_ADV_FETCH` |
| `calculate_custom_phoenix_score`, `explain_score_components` | Enterprise tier only |

Flags live on the server, not in this repository. Ask your Phoenix operator to
enable one. Do not change a flag yourself to make a skill pass.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401 API key required` | No key reached the server | Check `PHOENIX_API_KEY` is exported in the shell that launched Claude Code |
| `401 Invalid or expired API key` | Key unknown to this host | You are pointing at the wrong environment, or the key was revoked |
| `404 Not Found` on `tools/list` | Valid key, wrong scope | Get a `phx_api_power_` key or above |
| Tool list is short | Flags off or lower tier | See section 7 |
| Bridge exits at once | Python cannot find the script | Use an absolute path in `args` |
| TLS error on a self-hosted host | Self-signed certificate | Set `MCP_HTTP_INSECURE=1`. Never in production. |
