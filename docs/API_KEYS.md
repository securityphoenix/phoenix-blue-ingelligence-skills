# Phoenix API Keys — prefixes, scopes, and what each one unlocks

Every Phoenix key carries its scope in its own prefix. The prefix is not
cosmetic. The server reads it to decide which surfaces you may call, and a key
with the wrong prefix is refused even when it is otherwise valid.

Get a key from **My Account -> Platform API Keys** on your Phoenix instance.

---

## 1. The prefix table

Source of truth: `SCOPE_PREFIXES` in `backend/app/services/api_keys.py`.

| Prefix | Scope | Purpose |
|---|---|---|
| `phx_api_basic_` | `api_basic` | Registered-tier REST access |
| `phx_api_power_` | `api_power` | Pro-tier REST access |
| `phx_api_int_` | `api_integration` | Pro-tier integration access |
| `phx_api_unl_` | `api_unlimited` | Enterprise-tier access |
| `phx_mcp_` | `mcp` | MCP surface only |
| `phx_gintel_` | `api_global_intel` | Global Intel product bundle |
| `phx_fw_` | `api_firewall` | Supply Chain Firewall CLI / CI |
| `phx_fwagent_` | `firewall_agent` | Device-enrolled firewall agent |
| `phx_whk_` | `api_webhook` | Webhook ingress |
| `phx_reg_` / `phx_approve_` | `registration` / `approval` | Account admin flows |

---

## 2. Which key opens which door

This is the table that matters when a call fails.

| Surface | Accepted scopes | Refused key gets |
|---|---|---|
| **MCP** `POST /api/v1/mcp` | `api_power`, `api_integration`, `api_unlimited`, `mcp` | **404**, not 403 |
| **CRA library intelligence** `POST /api/v1/intel/library-versions` | `api_power`, `api_integration`, `api_unlimited` | **403** |
| **Package intel** `GET /api/v1/packages/intel` | same three | **403** |
| **Unified intel query** `/api/v1/intel/{entity}` | any valid REST key; `expanded` block needs Global Intel | **404** when the flag is off |
| **Firewall** `/api/v1/firewall/*` | `api_firewall`, `firewall_agent` | **401 / 403** |

### The 404 trap on MCP

A valid key that lacks the MCP scope does **not** get a 403. The server turns
that 403 into a **404** on purpose, so an unauthorised caller cannot learn that
MCP exists.

Source: `backend/app/mcp/auth.py`.

```python
if exc.status_code == 403:
    raise HTTPException(status_code=404, detail="Not Found")
```

So on MCP these three responses mean three different things:

| Response | Meaning |
|---|---|
| `401 {"detail":"API key required"}` | You sent no key |
| `401 {"detail":"Invalid or expired API key"}` | The key is unknown to this server |
| `404 {"detail":"Not Found"}` | The key is **valid** but lacks the MCP scope |

Verified live against a Phoenix backend on 2026-09-14. A `phx_gintel_` key
returned `404` while a deliberately bogus key returned `401` on the same call.
That difference is how you tell "wrong key type" from "wrong key".

---

## 3. Key to tier

Source of truth: `backend/app/services/tier_resolver.py`.

| Scope | Resolved tier |
|---|---|
| `api_basic` | Registered |
| `api_power` | Pro |
| `api_integration` | Pro |
| `api_unlimited` | Enterprise |

Tier controls *field shaping*. A Registered caller and an Enterprise caller can
hit the same endpoint and receive different keys in the body, because
`data_shield` strips fields above the caller's tier. `data_shield` runs
**fail-closed**: a field with no classification is dropped for everyone.

---

## 4. `phx_gintel_` is a product, not a permission

The Global Intel bundle raises the holder's intelligence tier and unlocks the
`expanded` block on the unified query surface. It is a **licence**. It is not an
authorisation, and it does not substitute for a REST or MCP scope.

Verified live: a `phx_gintel_` key returned `404` on MCP and `403` on the CRA
endpoint. It could not drive any part of the skills in this repository.

**If you only have a `phx_gintel_` key, request a `phx_api_power_` key or above.**

---

## 5. Choosing a key for this repository

| You want to | Use |
|---|---|
| Run both skills end to end | `phx_api_power_` or `phx_api_unl_` |
| MCP tools only, no REST | `phx_mcp_` |
| CRA upgrade answers only | `phx_api_power_` or above |
| Anything with `phx_gintel_` alone | Not possible — get a REST key too |

A single `phx_api_power_` key clears both the MCP gate and the CRA gate. That is
the simplest working setup.

---

## 6. Handling keys safely

- Put the key in an environment variable. Never in a committed file.
- This repository's `.mcp.json` IS tracked, on purpose: it is the Claude Code
  plugin manifest and holds only `${VAR}` references, never a value.
- Codex is the exception. It does **not** expand variables in
  `~/.codex/config.toml`, so the key is literal there. `chmod 600` that file.
- Keys are shown once at creation. Store them in a secret manager.
- Rotate a key the moment it appears in a chat log, a ticket, or a terminal
  transcript that other people can read.

```bash
export PHOENIX_API_KEY="phx_api_power_..."
export PHOENIX_MCP_URL="https://phxintel.security/api/v1/mcp"
```
