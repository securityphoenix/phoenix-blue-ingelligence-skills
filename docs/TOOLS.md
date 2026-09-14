# Phoenix intelligence surface reference

Two surfaces. MCP tools for interrogation. One REST endpoint for the upgrade
answer. This page lists both and says which one to trust for what.

A `*` marks a required argument.

---

## 1. MCP tools

Captured live from `tools/list` with an `api_unlimited` key on 2026-09-14.
Twenty-seven tools. Your list may be shorter — see
[MCP_SETUP.md section 7](MCP_SETUP.md#7-feature-flags-can-hide-tools).

### CVE intelligence

| Tool | What it returns | Arguments |
|---|---|---|
| `search_cves` | CVE list with PS-HP scoring | `query`, `year`, `severity`, `kev_only`, `ps_hp_min`, `ps_hp_tier`, `enterprise_watchlist`, `limit`, `offset` |
| `get_cve_intelligence` | Full CVE record with PS-HP / PS-EW | `cve_id*` |
| `get_phoenix_score` | PS-HP score with component breakdown | `cve_id*`, `include_rationale` |
| `explain_score_components` | Detailed PS-HP component explanation | `cve_id*` |
| `calculate_custom_phoenix_score` | PS-HP from hypothetical inputs | `cvss*`, `epss`, `in_kev`, `has_ransomware`, `exploit_status`, `vendor`, `product`, `github_stars`, `github_forks`, `bugbounty_reports` |
| `volerion_rescore` | Volerion rescore and delta | `cve_id*` |
| `get_high_profile_cves` | High-profile CVEs by tier | `tier`, `limit`, `enterprise_category` |
| `get_enterprise_watchlist` | PS-EW flagged enterprise blind spots | `category`, `limit` |
| `get_threat_actors_by_cve` | Threat actors linked to a CVE | `cve_id*` |
| `check_enterprise_critical` | Whether a vendor/product is enterprise-critical | `vendor*`, `product*` |
| `get_ai_attributed_cves` | CVEs found or co-reported by frontier AI models | `provider`, `program`, `min_cvss`, `since`, `limit` |

`calculate_custom_phoenix_score` and `explain_score_components` are Enterprise
tier only.

### CVE bundles

Requires `ENABLE_CVE_BUNDLES`.

| Tool | What it returns | Arguments |
|---|---|---|
| `bundles_for_cve` | Named advisory groupings containing a CVE | `cve_id*` |
| `get_bundle` | One bundle with all member CVE IDs | `bundle_id*` |

### End of life

| Tool | What it returns | Arguments |
|---|---|---|
| `list_eol_products` | EOL products, filterable | `status`, `category`, `vendor`, `search`, `limit`, `offset` |
| `get_eol_product` | One EOL product | `product_slug*` |
| `get_eol_cve_correlations` | CVEs on EOL or near-EOL products | `non_fixable_only`, `kev_only`, `min_cvss`, `limit`, `offset` |
| `get_cve_eol_status` | EOL status for one CVE | `cve_id*` |
| `get_eol_replacements` | Replacement recommendations | `category`, `limit` |
| `get_eol_replacement` | Replacement for one product | `product_slug*` |
| `get_eol_statistics` | Summary counts | *(none)* |
| `get_eol_timeline` | Upcoming EOL events | `days`, `category` |
| `get_eol_risk_score` | SLR risk score for a product | `product_slug*` |

### Supply chain firewall

Requires `enable_firewall_mcp_server`.

| Tool | What it returns | Arguments |
|---|---|---|
| `phoenix_check_package` | One package verdict: allow / warn / block | `purl*`, `enriched` |
| `phoenix_check_lockfile` | Batch verdicts with an aggregate pass or fail | `purls*` |
| `phoenix_get_package_intel` | PS-OSS score, malware signals, typosquat flag | `ecosystem*`, `name*` |
| `phoenix_get_alternatives` | Safe replacement packages | `ecosystem*`, `name*` |
| `phoenix_firewall_rules` | Your active firewall rules | *(none)* |

### Read this before you use the firewall tools for CVEs

**The firewall tools are a malware and supply-chain gate. They are not a CVE
scanner.** Do not read a `cve_count` from them as the vulnerability total.

Measured on the same library, same instance, same minute:

| Call | Result for `lodash@4.17.20` |
|---|---|
| `phoenix_get_package_intel` | `cve_count: 0`, `ps_oss_score: null` |
| `phoenix_check_lockfile` | `0 blocked, 0 warned, 3 allowed` |
| `POST /api/v1/intel/library-versions` | **10 CVEs**, upgrade to `4.18.0` |

Both answers are correct for their own question. `lodash` is not malware, so the
firewall allows it. It has ten known CVEs, which is what CRA reports. Use the
firewall for "is this package hostile". Use CRA for "is this version
vulnerable".

---

## 2. REST — the upgrade answer

### `POST /api/v1/intel/library-versions`

Capped batch, maximum 500 purls per call. This is the only surface that emits
`safe_upgrade_version`.

- **Auth:** `X-API-Key` header, Pro or Enterprise scope.
- **Flag:** `enable_cra_intel_surface`. Returns `404` when off, checked before
  auth.
- **Usage:** counted as one `batch_lookup`, not one per purl.

Request:

```json
{ "purls": ["pkg:npm/lodash@4.17.20", "pkg:pypi/requests@2.19.0"] }
```

Top-level response keys:

| Key | Meaning |
|---|---|
| `components` | One object per resolved purl |
| `unresolved` | Purls the corpus does not know |
| `rule_version` | Scoring contract version, currently `cra-v1` |
| `as_of` | Freshness per data source: `kev`, `shadowserver`, `library_intel` |

Per-component keys:

| Key | Meaning |
|---|---|
| `purl`, `ecosystem`, `name`, `version` | Component identity |
| `component_resolved` | Whether the corpus knew this component |
| `vulnerabilities` | Array of CVE rows, capped |
| `cra_vulnerability_total` | True total, which may exceed the array length |
| `cra_vulnerabilities_truncated` | `true` when the array was cut |
| `safe_upgrade_version` | **The upgrade target** |
| `cra_safe_upgrade_corroboration` | Caveat on that target. Four states. |
| `cra_safe_upgrade_reference` | Registry release above your version, or `null` |
| `cra_safe_upgrade_reference_state` | Why the reference is present or absent |
| `cra_safe_upgrade_reference_as_of` | Age of the reference data |

Per-CVE row keys:

| Key | Meaning |
|---|---|
| `cve_id`, `cvss`, `epss`, `severity` | Standard identity and scoring |
| `fixed_version` | Version this one CVE was fixed in |
| `affected_versions` | Range this CVE applies to |
| `exploitation_tier` | Evidence-based tier |
| `predicted_exploitation` | EPSS-based axis. Fails closed to `UNKNOWN`. |
| `cra_actively_exploited` | Backed by a verified KEV-class signal |
| `cra_potentially_exploited` | Tooling-only signal |
| `first_verified_exploited` | Date of first verified exploitation |
| `exploitation_evidence_rows` | Dated, citable evidence |
| `ransomware` | Linked to ransomware campaigns |
| `cra_version_match_undetermined` | The range could not be evaluated |

`exploitation_tier`, `predicted_exploitation`, `cra_potentially_exploited` and
`cra_inputs` are Pro-and-above fields. `data_shield` strips them below that.

Blue emits **evidence only**. It never emits a VEX `analysis.state`. Reachability
lives in your application graph, not here.

The contract for `safe_upgrade_version` has real traps in it. Read
[the upgrade contract](../skills/phoenix-library-upgrade/references/upgrade-contract.md)
before you consume the field.

---

## 3. Which surface answers which question

| Question | Use |
|---|---|
| Is this package malware? | `phoenix_check_package` |
| Is my lockfile safe to install? | `phoenix_check_lockfile` |
| Which CVEs affect this version? | `POST /api/v1/intel/library-versions` |
| What version do I upgrade to? | `POST /api/v1/intel/library-versions` |
| Is this CVE exploited in the wild? | `get_cve_intelligence` |
| How risky is this CVE, and why? | `get_phoenix_score` |
| Who is exploiting it? | `get_threat_actors_by_cve` |
| Is this product past end of life? | `get_cve_eol_status` |
| What do I use instead of this package? | `phoenix_get_alternatives` |
