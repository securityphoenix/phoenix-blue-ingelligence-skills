# Installing

This repository is a **marketplace** for both Claude Code and Codex. It ships
one plugin, `phoenix-blue-intelligence`, containing two skills and the Phoenix
MCP server.

| Agent | Marketplace manifest | Plugin manifest | MCP declared in |
|---|---|---|---|
| Claude Code | `.claude-plugin/marketplace.json` | `.claude-plugin/plugin.json` | `.mcp.json` |
| Codex | `.agents/plugins/marketplace.json` | `.codex-plugin/plugin.json` | `examples/codex-mcp-server.toml` |

Both read `skills/` for the skills themselves, so there is one copy of each
skill, not two.

---

## 1. Get a key first

Both agents need the same thing. From **My Account -> Platform API Keys** on
your Phoenix instance, create a **Pro or Enterprise** key. The prefix must be
`phx_api_power_`, `phx_api_int_`, or `phx_api_unl_`.

A `phx_gintel_` Global Intel key alone will not work. It is a product licence,
not an access scope. See [API_KEYS.md](API_KEYS.md).

```bash
export PHOENIX_API_KEY="phx_api_power_your_key_here"
export PHOENIX_API_URL="https://phxintel.security"
export PHOENIX_MCP_URL="https://phxintel.security/api/v1/mcp"
```

Put these in your shell profile so the agent inherits them at launch.

---

## 2. Claude Code

### Install from the marketplace

```
/plugin marketplace add securityphoenix/phoenix-blue-ingelligence-skills
/plugin install phoenix-blue-intelligence@phoenix-blue-intelligence
```

Restart Claude Code. You get:

- Two skills, invokable by name or by plain-language request.
- The MCP server, as `mcp__phoenix__*` tools.

### Install from a local clone

```bash
git clone https://github.com/securityphoenix/phoenix-blue-ingelligence-skills.git
```

```
/plugin marketplace add /absolute/path/to/phoenix-blue-ingelligence-skills
/plugin install phoenix-blue-intelligence@phoenix-blue-intelligence
```

### How the key reaches the server

`.mcp.json` names the variables. It never holds a value.

```json
"env": {
  "MCP_HTTP_URL": "${PHOENIX_MCP_URL}",
  "MCP_API_KEY":  "${PHOENIX_API_KEY}"
}
```

Claude Code expands them from the environment that launched it. If you exported
the variables after starting Claude Code, restart it.

### Verify

```
/plugin
```

The plugin should be listed as installed. Then ask the agent to list its tools,
or run the preflight yourself:

```bash
./scripts/check_setup.sh
```

---

## 3. Codex

### Add the marketplace

```
/plugins marketplace add https://github.com/securityphoenix/phoenix-blue-ingelligence-skills.git
/plugins install phoenix-blue-intelligence
```

Codex writes the marketplace into `~/.codex/config.toml`:

```toml
[marketplaces.phoenix-blue-intelligence]
source_type = "git"
source = "https://github.com/securityphoenix/phoenix-blue-ingelligence-skills.git"

[plugins."phoenix-blue-intelligence@phoenix-blue-intelligence"]
enabled = true
```

### Add the MCP server

Codex declares MCP servers in `~/.codex/config.toml`, not in a bundled
`.mcp.json`. Copy the block from `examples/codex-mcp-server.toml` and fill in the two
placeholders:

```toml
[mcp_servers.phoenix]
command = "python3"
args = ["/absolute/path/to/scripts/phoenix_mcp_bridge.py"]
startup_timeout_sec = 60

[mcp_servers.phoenix.env]
MCP_HTTP_URL = "https://phxintel.security/api/v1/mcp"
MCP_API_KEY = "phx_api_power_your_key_here"
MCP_HTTP_TIMEOUT = "60"
```

**Codex does not expand `${VARS}` in this file.** The values are literal, so the
key sits in `~/.codex/config.toml` in plain text. Keep that file at mode `600`
and never commit it.

```bash
chmod 600 ~/.codex/config.toml
```

### Skills only, without the MCP server

The `phoenix-library-upgrade` skill needs only the CRA REST endpoint, which it
calls with `curl` using `PHOENIX_API_KEY`. It works with no MCP at all. You lose
only the malware verdict in step 4 and the whole `phoenix-cve-intel` skill.

---

## 4. Manual install, no marketplace

Both agents read skills from a directory. Copy them in.

**Claude Code:**

```bash
cp -r skills/phoenix-library-upgrade ~/.claude/skills/
cp -r skills/phoenix-cve-intel       ~/.claude/skills/
```

Project-scoped instead of user-scoped: `.claude/skills/` in the project root.

**Codex:**

```bash
cp -r skills/phoenix-library-upgrade ~/.codex/skills/
cp -r skills/phoenix-cve-intel       ~/.codex/skills/
```

The skill folders are plain `SKILL.md` plus `references/`. Both agents read the
same YAML frontmatter, so no conversion is needed.

Codex additionally reads an optional `openai.yaml` beside `SKILL.md` for the
display name and default prompt. Its absence is harmless — the skill still
loads from the frontmatter.

### Fix the relative paths after a manual copy

Both `SKILL.md` files link to `../../docs/*.md` and call
`scripts/reachability.py`. Those paths resolve inside the repository. After
copying a skill folder out on its own, either copy `docs/` and `scripts/`
alongside it, or use the marketplace install, which keeps the layout intact.

---

## 5. Verify, whichever route you took

```bash
./scripts/check_setup.sh
```

It checks the host, the key scope, the MCP surface, and the CRA upgrade
endpoint, and names the feature flag behind every failure.

Expected on a healthy Pro or Enterprise key:

```
1. API key          [ OK ] scope clears both MCP and the CRA upgrade surface
2. Host             [ OK ] responded 200
3. MCP surface      [ OK ] MCP reachable, 27 tools visible
4. CRA upgrade      [ OK ] CRA reachable
Result: 5 passed, 0 failed.
```

A `404` on step 3 means the key is valid but lacks the MCP scope. A `404` on
step 4 means the `enable_cra_intel_surface` flag is off on that instance. Both
are server-side. Do not work around them.

---

## 6. Updating

**Claude Code:**

```
/plugin marketplace update phoenix-blue-intelligence
```

**Codex:**

```
/plugins marketplace update phoenix-blue-intelligence
```

Codex records `last_updated` and `last_revision` per marketplace in
`~/.codex/config.toml`, so it can tell you what changed.

---

## 7. Removing

**Claude Code:**

```
/plugin uninstall phoenix-blue-intelligence@phoenix-blue-intelligence
/plugin marketplace remove phoenix-blue-intelligence
```

**Codex:**

```
/plugins uninstall phoenix-blue-intelligence
```

Then delete the `[mcp_servers.phoenix]` and `[mcp_servers.phoenix.env]` blocks
from `~/.codex/config.toml`. Uninstalling the plugin does not remove them,
and they hold your key.
