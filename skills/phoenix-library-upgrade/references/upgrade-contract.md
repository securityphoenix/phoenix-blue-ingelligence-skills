# The `safe_upgrade_version` contract

Read this before you present an upgrade to anyone. The field has three possible
shapes and a mandatory caveat. Getting it wrong tells a user to install a
version that does not fix their problem, or one that moves them backwards.

---

## 1. What the field claims, exactly

`safe_upgrade_version` is the **highest version any advisory asserts as the fix**
for a CVE affecting this component. It is `max(fixed_version)` across the
component's known CVE rows.

That is all it claims. It is not a compatibility check. It is not a test run. It
does not know whether your code still works afterwards.

---

## 2. Three shapes. Handle all three.

| Shape | Example | What it means | What you do |
|---|---|---|---|
| A version string | `"4.18.0"` | An advisory names this as the fix | Recommend it, with the caveat from section 3 |
| The token `"latest"` | `"latest"` | CVEs exist, but no advisory names any fix | Say "move to the newest release". Never print it as a version number. |
| `null` | `null` | Either no CVEs, or the CVE list was truncated | Give no upgrade. Check `cra_vulnerability_total`. |

### `"latest"` is a directive, not a version

Compare it with equality. Never parse it as a semver. Never sort it.

It is deliberately unresolved. Resolving it from the record's own
`latest_version` was considered and rejected, because that field is wrong in the
dangerous direction: `lodash` carries `latest_version="4.9.0"` while the real
latest is `4.17.21`. Emitting it would tell a user on `4.17.20` to move
**backwards**, behind every fix in CVE-2021-23337, CVE-2020-8203,
CVE-2019-10744 and CVE-2018-3721.

### `null` has two causes. They are not the same.

```
cra_vulnerability_total == 0   ->  nothing to fix. Good news.
cra_vulnerabilities_truncated  ->  the list was cut. NO ANSWER IS SAFE.
```

A max over a partial list names a version that does not clear every CVE. The
server withholds the answer rather than emit a wrong one. You must do the same.
Say "the vulnerability list was truncated, so no upgrade target can be
computed". Do not guess from the rows you can see.

---

## 3. The caveat is mandatory

Every upgrade ships with `cra_safe_upgrade_corroboration`. It has **four**
states. Print it. Always.

| State | Meaning | How to say it |
|---|---|---|
| `corroborated` | The target was cross-checked against a known release and holds up | "Verified against the published release list." |
| `exceeds_known_latest` | An advisory names a version above any release we can see | "One advisory names a version newer than the latest release we know of. Confirm it exists before upgrading." |
| `no_reference_version` | No release data existed, so no check ran | "Not cross-checked — no release data for this package." |
| `no_known_fix` | CVEs exist, no advisory names a fix. Pairs with `"latest"`. | "No advisory names a fix. Move to the newest release and retest." |

### Why four states and not a boolean

An earlier version of this field was a boolean, `unverified: true/false`. It
shipped a subtler version of the bug this whole contract exists to prevent.

Measured on 8,623 live components carrying a `safe_upgrade_version`:

| Outcome | Count | Share |
|---|---|---|
| No release data, so no check ran | 7,925 | 92% |
| Checked, and it held up | 631 | 7% |
| Checked, and it flagged | 67 | 1% |

A boolean collapses the first two rows into the same `false`. "Checked, fine"
and "never checked" then read identically. A reader seeing `unverified: false`
on 92% of components reasonably concludes verification happened and passed. It
did not happen at all.

That is worse than showing the bare version with no caveat. Three real states,
plus `no_known_fix`, so "not corroborated" and "never checked" stay separate
answers.

**Never collapse these four into "verified" and "unverified". Never hide them
to keep a report tidy.**

---

## 4. The reference release fields

When `safe_upgrade_version` is the `"latest"` directive, three more fields try to
resolve it into a real number.

| Field | Meaning |
|---|---|
| `cra_safe_upgrade_reference` | A registry release strictly above your submitted version, or `null` |
| `cra_safe_upgrade_reference_state` | Why it is present or absent |
| `cra_safe_upgrade_reference_as_of` | How old that claim is |

`cra_safe_upgrade_reference_state` values:

| State | Meaning |
|---|---|
| `registry_latest_stable` | A real release above your version. Use it. |
| `not_above_submitted` | A release exists but is at or below your version. Withheld — useless as a target. |
| `no_registry_reference` | No registry release for this component. |
| `not_applicable` | The target is already a real version, so there was no directive to resolve. |

Two invariants protect you. A reference is **never** emitted unless it is
strictly above your submitted version, so a stale snapshot yields an absence
with a reason rather than a number pointing backwards. And the snapshot age
always travels with it, so you can see how old the claim is instead of assuming
it is current.

---

## 5. Worked examples, measured live

All three from one call on 2026-09-14.

### `pkg:npm/lodash@4.17.20`

```
cra_vulnerability_total:            10
cra_vulnerabilities_truncated:      false
safe_upgrade_version:               "4.18.0"
cra_safe_upgrade_corroboration:     "exceeds_known_latest"
```

How to report it: "10 known CVEs. One advisory names `4.18.0` as the fix, which
is newer than any release we can see. Confirm `4.18.0` exists before you plan
the upgrade. The CVE rows themselves name `4.17.21` for the three most severe
issues."

Do **not** report it as "upgrade to 4.18.0" with no caveat.

### `pkg:pypi/requests@2.19.0`

```
cra_vulnerability_total:            8
safe_upgrade_version:               "2.33.0"
cra_safe_upgrade_corroboration:     "exceeds_known_latest"
```

Same treatment. The caveat is not optional because the number looks plausible.

### `pkg:npm/express@4.17.1`

```
cra_vulnerability_total:            10
safe_upgrade_version:               "4.22.0"
cra_safe_upgrade_corroboration:     "corroborated"
```

How to report it: "10 known CVEs. Upgrade to `4.22.0`. Verified against the
published release list."

This is the only one of the three you may state plainly.

---

## 6. Rules, in one list

1. Never compute an upgrade version yourself. Read `safe_upgrade_version`.
2. Never parse `"latest"` as a version number.
3. Never print an upgrade without its corroboration state.
4. Never turn `null` into a guess. Check `cra_vulnerabilities_truncated` first.
5. Never use `latest_version` as an upgrade target. It can point backwards.
6. Always carry `as_of.library_intel` so the reader can see the data's age.
7. Always say that Phoenix emits evidence, not a fix verdict. Compatibility and
   reachability are the caller's to determine.
