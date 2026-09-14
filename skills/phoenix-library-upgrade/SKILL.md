---
name: phoenix-library-upgrade
description: Find which libraries in a project are vulnerable, which CVEs affect the pinned version, whether the library is a direct or transitive dependency, whether the code actually calls the vulnerable function, and which version to upgrade to. Use when the user asks to scan dependencies, check a lockfile, audit packages for CVEs, find vulnerable libraries, ask if a vulnerability is reachable or exploitable in this codebase, or asks what version fixes a vulnerability. Queries the Phoenix Blue intelligence platform over MCP and REST, then measures reachability locally.
---

# Phoenix library upgrade intelligence

Answers five questions about a project's dependencies:

1. Which libraries are vulnerable?
2. Which CVEs affect the pinned version?
3. Is the library a **direct** or an **indirect** (transitive) dependency?
4. Does this codebase actually **call** the vulnerable function?
5. Which version do I upgrade to?

Questions 3 and 4 are measured **locally, in the user's repository**. Phoenix
does not publish the vulnerable function name, so it cannot answer them. Read
`references/reachability.md` before you run them.

Question 5 has its own traps. **Read `references/upgrade-contract.md` before you
report any upgrade.** It is not optional context. It is the contract.

---

## Before you start

You need:

- `PHOENIX_API_KEY` exported, with a Pro or Enterprise scope
  (`phx_api_power_`, `phx_api_int_`, `phx_api_unl_`).
- `PHOENIX_API_URL` exported, for example `https://phxintel.security`.
- The Phoenix MCP server registered, for step 4 only.

A `phx_gintel_` key alone will **not** work. It is a product licence, not an
access scope. See `docs/API_KEYS.md`.

---

## Step 1 — Preflight

Check the surfaces before you promise anything.

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$PHOENIX_API_URL/api/v1/intel/library-versions" \
  -H "Content-Type: application/json" -H "X-API-Key: $PHOENIX_API_KEY" \
  -d '{"purls":["pkg:npm/lodash@4.17.20"]}'
```

| Code | Meaning | What you do |
|---|---|---|
| `200` | Working | Continue |
| `403` | Key scope too low | Stop. Tell the user they need a Pro or Enterprise key. |
| `404` | Flag `enable_cra_intel_surface` is off | Stop. Tell the user to ask their operator to enable it. |
| `401` | Key unknown to this host | Stop. Wrong environment, or revoked key. |

Do not retry a `403` or a `404`. Neither will change on a second attempt. Report
the exact code and stop.

---

## Step 2 — Collect the purls

Build a list of package URLs from whatever the user has.

| Source | How |
|---|---|
| `package-lock.json` | `packages` object keys plus each `version` |
| `yarn.lock` | each entry's resolved name and version |
| `requirements.txt` | pinned `name==version` lines only |
| `poetry.lock` | `[[package]]` `name` and `version` |
| `go.sum` / `go.mod` | `require` block |
| `Gemfile.lock` | `specs:` section |
| `pom.xml` | `groupId:artifactId:version` |

Purl format: `pkg:<ecosystem>/<name>@<version>`

```
pkg:npm/lodash@4.17.20
pkg:npm/@scope/name@1.2.3
pkg:pypi/requests@2.19.0
pkg:maven/org.apache.commons/commons-lang3@3.9
pkg:golang/github.com/gin-gonic/gin@v1.7.0
```

Rules:

- Skip unpinned ranges such as `^4.17.0`. You cannot assess a range.
- Split into batches of 500. That is the server's hard cap.
- Tell the user how many you skipped and why.

---

## Step 3 — Ask for the vulnerabilities and the upgrade

One call per batch.

```bash
curl -s -X POST "$PHOENIX_API_URL/api/v1/intel/library-versions" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PHOENIX_API_KEY" \
  -d '{"purls": ["pkg:npm/lodash@4.17.20", "pkg:pypi/requests@2.19.0"]}'
```

This one call returns the CVE list **and** the upgrade target. It is the primary
source for both.

Read these per component:

- `cra_vulnerability_total` — the true CVE count. Use this, not
  `len(vulnerabilities)`.
- `cra_vulnerabilities_truncated` — if `true`, the array is partial.
- `safe_upgrade_version` — the upgrade target.
- `cra_safe_upgrade_corroboration` — the mandatory caveat.
- `vulnerabilities[]` — per-CVE detail with `fixed_version` and
  `affected_versions`.

Read these once, at the top level:

- `unresolved` — purls the corpus does not know. Report them as unknown, never
  as clean.
- `as_of.library_intel` — the data's age. Always carry it into the report.

---

## Step 4 — Add the malware verdict (optional)

The CRA call covers known CVEs. It does not cover malware or typosquats. Add
that from MCP if the tools are available.

```
mcp__phoenix__phoenix_check_lockfile
  purls: [...same list...]
```

Returns `pass`, `blocked_count`, `warned_count`, and per-package `action`.

**Do not read CVE counts from the firewall tools.** They answer a different
question. On the same `lodash@4.17.20`, `phoenix_get_package_intel` reports
`cve_count: 0` while CRA reports 10 CVEs. Both are right. The firewall checks
whether a package is hostile. CRA checks whether a version is vulnerable.

If the tools are missing, say so and carry on. Their absence means
`enable_firewall_mcp_server` is off, not that the packages are clean.

---

## Step 5 — Assess local reachability

Only for components that came back with CVEs. Phoenix cannot answer this. You
measure it in the repository.

**Read `references/reachability.md` first.** It carries the search patterns per
ecosystem and the limits of each one.

### The fast path

`scripts/reachability.py` runs all four levels and returns JSON. Prefer it over
hand-typed greps — it already handles import aliases, PEP 503 name
normalisation, dependency-directory exclusion, and the priority rules.

```bash
python3 scripts/reachability.py --root . --purl pkg:npm/lodash@4.17.20 \
  --severity CRITICAL \
  --cve CVE-2021-23337 "...Command Injection via the template function." \
  --cve CVE-2020-28500 "...via the toNumber, trim and trimEnd functions."
```

Pass `--actively-exploited` or `--ransomware` when the Phoenix row says so. Both
force P1 and ignore every local signal.

Covers npm, pypi, golang, gem, cargo, maven, composer, nuget. An unsupported
ecosystem returns an explicit error, never a silent pass.

The manual steps below are the fallback when the script cannot run, and the
explanation of what it is doing.

Four levels, in order. Stop where you run out of evidence and say where you
stopped.

**L1 — direct or indirect.** Compare the manifest against the lockfile.

```bash
# npm: is it in package.json, and what pulled it in?
python3 -c "import json;d=json.load(open('package.json'));print(sorted({**d.get('dependencies',{}),**d.get('devDependencies',{})}))"
npm ls lodash
```

A direct dependency you can upgrade yourself. A transitive one may need its
parent to move first. Name the parent in the report.

**L2 — is it imported at all.** Search first-party source. Exclude the
dependency directory, or everything looks used.

```bash
grep -rn --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build \
  -E "(require\(['\"]lodash(/[^'\"]*)?['\"]\)|from ['\"]lodash(/[^'\"]*)?['\"])" .
```

The package name and the import name often differ. `PyYAML` imports as `yaml`.
Check the alias table in the reference before you report an absence.

**L3 — which symbols are called.** Take the alias from each import, then
enumerate its member accesses.

```bash
# Portable: BSD sed (macOS) has no \b, so the word boundary lives in grep only.
grep -rhoE "(^|[^A-Za-z0-9_])_\.[a-zA-Z_][a-zA-Z0-9_]*" \
  --include='*.js' --include='*.ts' --exclude-dir=node_modules . \
  | sed -E 's/.*_\.//' | sort -u
```

A deep import such as `require('lodash/template')` names the symbol in its own
path. That is the strongest signal available.

**L4 — does the CVE name a symbol we call.** Pull candidate function names out
of the CVE description, then intersect with the L3 set.

```
"...vulnerable to Command Injection via the template function."
   -> template

"...via the toNumber, trim and trimEnd functions."
   -> toNumber, trim, trimEnd
```

Match on `via|in|within|through|using|from the <A>, <B> and <C> function(s)`,
on backticked identifiers, and on dotted paths. A camelCase regex alone misses
`template` and `trim`.

### The rule that outranks the whole step

**You may lower a priority. You may never clear a finding.**

Static search cannot see dynamic imports, reflection, re-exports, plugin
loaders, build-time generation, or a dependency calling the vulnerable code on
your behalf. Many CVEs are not "function X is unsafe" at all — prototype
pollution and parser bugs have no call site to find.

Banned words for any reachability result: "not affected", "not vulnerable",
"safe", "false positive".

Required words: "no first-party usage found", "lower priority", "investigate",
"could not determine".

"Could not determine" always outranks "looks unused". An unknown is not a
negative.

---

## Step 6 — Report

One table. Sort by priority, then by CVE count.

```
Library            Pinned    Dep    CVEs  Reachability        Upgrade to  Confidence                  Pri
------------------ --------- ------ ----- ------------------- ----------- --------------------------- ---
pkg:npm/lodash     4.17.20   direct 10    _.template called   4.18.0      newer than any known rel.   P1
pkg:npm/express    4.17.1    direct 10    imported, no match  4.22.0      verified against releases   P2
pkg:pypi/requests  2.19.0    via boto3  8 no import found     2.33.0      newer than any known rel.   P3

Data as of 2026-09-14T14:14:41Z. Malware scan: 0 blocked, 0 warned.
Unresolved (not in corpus, NOT assessed): none.

Reachability was measured by searching this repository, not by Phoenix.
Static search cannot see dynamic or reflective calls, so a low result lowers
priority and never clears a finding.
```

Translate the corroboration state into plain words. Never print the raw enum
alone.

### Priority table

Phoenix owns the left column. Your local search owns the middle one.

| Exploitation (Phoenix) | Local reachability | Priority |
|---|---|---|
| `cra_actively_exploited: true` | any, including unknown | **P1** |
| `ransomware: true` | any | **P1** |
| High severity | Direct, symbol matched | **P1** |
| High severity | Direct, imported, no symbol match | **P2** |
| High severity | Transitive, imported via a parent | **P2** |
| High severity | Transitive, no first-party import | **P3** |
| Medium or low | Imported | **P3** |
| Medium or low | No first-party import found | **P4** |
| Any | Could not determine | **P2 — never P4** |

An actively-exploited CVE stays P1 no matter what the local search found.

| Enum | Plain words |
|---|---|
| `corroborated` | verified against releases |
| `exceeds_known_latest` | newer than any known release — confirm it exists |
| `no_reference_version` | not cross-checked — no release data |
| `no_known_fix` | no advisory names a fix — move to newest and retest |

Then add the highest-risk detail. For each component with
`cra_actively_exploited: true` or `ransomware: true`, name the CVE and say why
it is urgent.

---

## Hard rules

1. **Never compute an upgrade version yourself.** Read `safe_upgrade_version`.
   Do not take a max over `fixed_version` values. The server already does this,
   and it refuses to answer on a truncated list for a reason.
2. **Never parse `"latest"` as a version number.** It is a token. Compare with
   equality.
3. **Never print an upgrade without its corroboration state.**
4. **Never turn `null` into a guess.** Check `cra_vulnerabilities_truncated`.
5. **Never report `unresolved` purls as clean.** They were not assessed.
6. **Never clear a finding on reachability evidence.** Lower its priority, and
   say what the search cannot see.
7. **Never call a reachability result "not affected", "not vulnerable", "safe",
   or "a false positive".**
8. **Never claim Phoenix assessed reachability.** It did not. You searched the
   repository. Say which.
9. **Never drop an actively-exploited CVE below P1**, whatever the local search
   found.
10. **Never present this as a fix verdict.** Phoenix emits evidence.
    Compatibility is the user's call.
11. **Never flip a feature flag** to make a call succeed. Report the gate and
    stop.

---

## When things are missing

| Situation | Say this |
|---|---|
| CRA returns `404` | "The CRA intelligence surface is switched off on this instance. Ask your operator to enable `enable_cra_intel_surface`." |
| CRA returns `403` | "This key is below Pro tier. The upgrade surface needs a `phx_api_power_` key or above." |
| Firewall tools absent | "Malware verdicts are unavailable — `enable_firewall_mcp_server` is off. CVE results below are unaffected." |
| A purl is in `unresolved` | "Not in the corpus. Not assessed. This is not a clean result." |
| No source files to search | "Reachability could not be measured — no first-party source found. Priority is based on Phoenix evidence alone." |
| The CVE names no function | "The CVE text does not name a function, so reachability could not be narrowed past 'is it imported'." |
| The code is minified or vendored | "Aliases are mangled. Symbol-level reachability is not measurable here." |
| `cra_vulnerabilities_truncated` is `true` | "The CVE list was truncated, so no safe upgrade target can be computed for this component." |

---

## Reference files

- `references/upgrade-contract.md` — the three shapes, the four caveat states,
  and the measured reasons behind them. **Read before reporting.**
- `references/reachability.md` — the four levels, per-ecosystem search patterns,
  the eight blind spots, and the priority table. **Read before step 5.**
- `references/lockfile-parsing.md` — purl extraction per ecosystem.
- `../../docs/TOOLS.md` — full field reference.
- `../../docs/API_KEYS.md` — which key opens which door.
