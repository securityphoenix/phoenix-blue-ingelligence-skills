# Examples

Manual MCP setup, for people who do not install the plugin from the
marketplace. Marketplace users need neither file.

| File | For | Copy to |
|---|---|---|
| `mcp-manual-setup.json` | Claude Code, without the plugin | `.mcp.json` in your project, or `~/.claude.json` |
| `examples/codex-mcp-server.toml` | Codex | append to `~/.codex/config.toml` |

## The two `.mcp.json` shapes are different

This trips people up, so it is stated plainly.

A **plugin** ships `.mcp.json` as a **bare map** of server name to config:

```json
{ "phoenix": { "command": "python3", "args": ["..."] } }
```

A **project or user** `.mcp.json` wraps the same thing in `mcpServers`:

```json
{ "mcpServers": { "phoenix": { "command": "python3", "args": ["..."] } } }
```

The `.mcp.json` at this repository's root is the **plugin** form. Do not copy
`mcp-manual-setup.json` over it — that would break the plugin. Copy it into
your own project instead.

## Paths and keys

`mcp-manual-setup.json` uses an absolute path, because outside a plugin there
is no `${CLAUDE_PLUGIN_ROOT}` to expand. Replace it.

Claude Code expands `${PHOENIX_API_KEY}` from the environment, so no key is
written to the file. **Codex does not expand variables** in `config.toml`, so
the key is literal there. Keep `~/.codex/config.toml` at mode `600`.
