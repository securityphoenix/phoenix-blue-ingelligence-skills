# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version in `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` and
`.claude-plugin/marketplace.json` always matches the latest git tag. Pin to a
tag, never to a branch. See [docs/INSTALL.md](docs/INSTALL.md#8-pinning-a-version).

---

## [1.0.0] — 2026-09-14

First release. Installable as a marketplace by both Claude Code and Codex.

### Added

**Skills**

- `phoenix-library-upgrade` — scan a project's dependencies, return the CVEs
  affecting each pinned version, and the safe upgrade target with its
  corroboration caveat. Then measure, locally, whether the vulnerable code is
  reachable: direct or transitive dependency, import presence, symbol usage,
  and whether the CVE names a symbol the code calls.
- `phoenix-cve-intel` — interrogate CVE, exploitation, threat-actor and
  end-of-life intelligence over MCP.

**Scripts**

- `scripts/phoenix_mcp_bridge.py` — stdio-to-HTTP MCP bridge.
- `scripts/check_setup.sh` — preflight that names the feature flag behind
  every failure, for the key, the host, the MCP surface and the CRA endpoint.
- `scripts/reachability.py` — local reachability analysis across npm, pypi,
  golang, gem, cargo, maven, composer and nuget.

**Packaging**

- Claude Code marketplace (`.claude-plugin/`) and plugin MCP manifest
  (`.mcp.json`, bare-map form).
- Codex marketplace (`.agents/plugins/`), plugin manifest (`.codex-plugin/`),
  and per-skill `openai.yaml` display metadata.
- Manual setup examples under `examples/`, deliberately outside the repository
  root so copying one cannot overwrite the plugin's own `.mcp.json`.

**Documentation**

- `docs/INSTALL.md` — marketplace install for both agents, manual install,
  version pinning, updating, removal.
- `docs/API_KEYS.md` — all 12 key prefixes, which surface each opens, and how
  to read a failure.
- `docs/MCP_SETUP.md` — endpoints, environment variables, troubleshooting.
- `docs/TOOLS.md` — 27 MCP tools and every CRA response field.
- `references/upgrade-contract.md` — the three shapes of
  `safe_upgrade_version` and its four-state caveat.
- `references/reachability.md` — the four levels and eight blind spots.
- `references/lockfile-parsing.md` — purl extraction for ten ecosystems.

### Behaviour worth knowing

These were verified against a live Phoenix backend, not assumed.

- **A `phx_gintel_` key cannot drive these skills.** Global Intel is a product
  licence, not an access scope. It returns `404` on MCP and `403` on the CRA
  endpoint. Use `phx_api_power_`, `phx_api_int_`, or `phx_api_unl_`.
- **MCP returns `404`, not `403`, for a valid key with the wrong scope**, so an
  unauthorised caller cannot learn that MCP exists. `401` means the key is
  unknown; `404` means the key is fine but lacks the scope.
- **The firewall MCP tools are a malware gate, not a CVE scanner.** On
  `lodash@4.17.20` they report `cve_count: 0` and `allow`, while the CRA
  endpoint reports 10 CVEs. Both are correct for their own question.
- **Reachability never clears a finding.** It lowers priority. Static search
  cannot see dynamic imports, reflection, re-exports, or a dependency calling
  the vulnerable code on your behalf, and many CVEs have no call site at all.
  An actively-exploited CVE stays P1 whatever the search found.
- **`safe_upgrade_version` is not always a version.** It can be the token
  `"latest"` or `null`. Its `cra_safe_upgrade_corroboration` caveat has four
  states, and 92% of live components land on `no_reference_version`.

### Requires

- Python 3.8 or newer. The bridge and the analyser use only the standard
  library.
- A Phoenix Pro or Enterprise API key.
- Server-side flags: `enable_cra_intel_surface` for upgrade answers,
  `enable_firewall_mcp_server` for malware verdicts. Both are the Phoenix
  operator's to set.

[1.0.0]: https://github.com/securityphoenix/phoenix-blue-ingelligence-skills/releases/tag/v1.0.0
