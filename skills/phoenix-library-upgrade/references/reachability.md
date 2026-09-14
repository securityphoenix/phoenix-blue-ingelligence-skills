# Local reachability assessment

Phoenix tells you a library version is vulnerable. It does **not** tell you
whether your code can reach the vulnerable part. Phoenix does not publish the
vulnerable function name at all.

So reachability is measured **locally, in the user's repository**, by the agent.

This file says how, and — more importantly — says exactly how far the answer can
be trusted.

---

## 1. The one rule that outranks everything here

**You may lower a priority. You may never clear a finding.**

Every level below is evidence, not a verdict. Static text search cannot see
dynamic imports, reflection, string-built call names, plugin loaders,
re-exports, build-time code generation, eval, or a transitive dependency calling
the vulnerable code on your behalf.

Forbidden words for any result on this page: "not affected", "not vulnerable",
"safe", "false positive", "no action needed".

Permitted words: "no first-party usage found", "lower priority", "investigate",
"could not determine".

An absence of evidence is not evidence of absence. Say so in the report.

---

## 2. Four levels, from solid to speculative

| Level | Question | Method | Trust |
|---|---|---|---|
| **L1** | Direct or transitive? | Manifest against lockfile | **High** |
| **L2** | Is the package imported in first-party code? | Import search across source | **High** when absent, medium when present |
| **L3** | Which of its symbols does the code call? | Call-site search at each import alias | **Medium** |
| **L4** | Does the CVE name a symbol we call? | CVE text against the L3 set | **Low — a hint** |

Run them in order. Stop early if a level cannot run, and say which one stopped.

---

## 3. L1 — direct or transitive

A **direct** dependency is one the project's own manifest asks for. Everything
else arrived because something else wanted it.

| Ecosystem | Direct means listed in | Full set lives in |
|---|---|---|
| npm | `package.json` `dependencies` / `devDependencies` | `package-lock.json` |
| Python | `pyproject.toml`, `requirements.in`, or top-level `requirements.txt` | `poetry.lock`, `Pipfile.lock` |
| Go | `go.mod` `require` without `// indirect` | `go.sum` |
| Ruby | `Gemfile` | `Gemfile.lock` |
| Rust | `Cargo.toml` `[dependencies]` | `Cargo.lock` |
| Maven | `pom.xml` `<dependencies>` | `mvn dependency:tree` |
| .NET | `.csproj` `PackageReference` | `packages.lock.json` |

Why it matters:

- **Direct** — you chose it. You can usually upgrade it yourself.
- **Transitive** — a parent pinned it. Upgrading may need the parent to move
  first, or an override / resolution entry.

For a transitive finding, also name the parent. npm:

```bash
npm ls lodash
```

Python, Go, Maven equivalents: `pipdeptree -r -p <pkg>`, `go mod why <module>`,
`mvn dependency:tree -Dincludes=<groupId>:<artifactId>`.

Record the shortest path, for example `express -> body-parser -> qs`. The user
needs it to plan the fix.

L1 is deterministic. Report it plainly.

---

## 4. L2 — is the package imported at all

Search first-party source only. **Exclude the dependency directory**, or every
package will look used because its siblings import it.

| Ecosystem | Exclude | Search for |
|---|---|---|
| npm | `node_modules/`, `dist/`, `build/`, `*.min.js` | `require('name')`, `from 'name'`, `import('name')` |
| Python | `.venv/`, `site-packages/` | `import name`, `from name import` |
| Go | `vendor/` | the module path in an import block |
| Ruby | `vendor/bundle/` | `require 'name'` |
| Rust | `target/` | `use name::`, `extern crate name` |
| Java | `target/`, `build/` | `import group.artifact.` |

Example, npm:

```bash
grep -rn --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build \
  -E "(require\(['\"]lodash(/[^'\"]*)?['\"]\)|from ['\"]lodash(/[^'\"]*)?['\"])" .
```

Example, Python. Normalise the name first: the distribution `PyYAML` imports as
`yaml`, `beautifulsoup4` as `bs4`, `Pillow` as `PIL`.

```bash
grep -rn --include='*.py' --exclude-dir=.venv --exclude-dir=site-packages \
  -E "^\s*(import\s+requests|from\s+requests(\.|\s+import))" .
```

### Reading the L2 result

| Outcome | Say |
|---|---|
| Imports found | "Imported in N files." Continue to L3. |
| No imports found, dependency is **transitive** | "No first-party import found. Reached only through `<parent>`." Lower priority. |
| No imports found, dependency is **direct** | "Declared but no import found. It may be unused, or loaded dynamically." Flag it — an unused direct dependency is worth removing. |

Package name and import name differ often. If L2 finds nothing, check the
alias table above before you report an absence.

---

## 5. L3 — which symbols are called

For each import found in L2, capture the local alias, then search for its call
sites.

```js
import _ from 'lodash'          // alias _        -> search  _.
import { template } from 'lodash'  // named        -> template( is called directly
const lodash = require('lodash')   // alias lodash -> search  lodash.
import tpl from 'lodash/template'  // deep import  -> tpl( , and the path names the symbol
```

A **deep import** is the strongest signal on this page. `require('lodash/template')`
names the symbol in the path itself. No inference needed.

A **namespace import** (`import _ from 'lodash'`) is the weakest. `_.` could be
anything, so you must enumerate the member accesses:

```bash
# Portable: BSD sed (macOS) has no \b, so the word boundary lives in grep only.
grep -rhoE "(^|[^A-Za-z0-9_])_\.[a-zA-Z_][a-zA-Z0-9_]*" \
  --include='*.js' --include='*.ts' --exclude-dir=node_modules . \
  | sed -E 's/.*_\.//' | sort -u
```

That yields the set of lodash members the project actually touches. Keep it. L4
needs it.

Report the set, capped at around 20 entries, with a count of the rest.

---

## 6. L4 — does the CVE name a symbol we call

**This is a hint. Label it as one, every time.**

Phoenix's CVE description often names the vulnerable function in prose. Extract
candidates, then intersect with the L3 set.

Real descriptions, and what to pull from them:

```
"Lodash versions prior to 4.17.21 are vulnerable to Command Injection
 via the template function."
   -> template

"Lodash versions prior to 4.17.21 are vulnerable to Regular Expression
 Denial of Service (ReDoS) via the toNumber, trim and trimEnd functions."
   -> toNumber, trim, trimEnd
```

Patterns that work, in priority order:

1. `via|in|within|through|using|from the <A>, <B> and <C> function(s)|method(s)`
2. A backticked call, `` `parse_url()` ``
3. Any backticked identifier of 3 or more characters
4. A dotted path such as `urllib3.util.parse_url`

Strip filler words: `the and or a an of in via function functions method methods`.

A naive camelCase regex is **not** enough. It finds `toNumber` and `trimEnd` but
misses `template` and `trim`, which are plain lowercase words. Use the patterns
above.

### Reporting L4

| Intersection | Say |
|---|---|
| Non-empty | "The CVE text names `template`, and the code calls `_.template` in 3 files. Treat as likely reachable." |
| Empty, L3 set is known | "The CVE text names `template`. No call to it was found among the 14 lodash members this project uses. Lower priority — **not a clearance**." |
| No symbol extractable | "The CVE text does not name a function. Reachability could not be narrowed below L2." |

Never write "the vulnerable function is not called". Write "no call to it was
found".

---

## 7. Where this is blind

State these in the report whenever an L2, L3 or L4 result lowers a priority.
The user must be able to judge your confidence.

| Blind spot | Example |
|---|---|
| Dynamic import | `require(pkgName)` where `pkgName` is a variable |
| Reflection | `getattr(mod, name)`, `Class.forName(s)` |
| Re-export | Your own `utils.js` wraps lodash; callers never name it |
| Transitive call | A dependency you *do* import calls the vulnerable code for you |
| Build-time generation | Code emitted by a bundler, codegen, or macro |
| Config-driven loading | Plugin name in a YAML file |
| Non-function vulnerability | Prototype pollution, a parser bug, a default setting — there is no call site to find |
| Minified or vendored code | Aliases are mangled beyond matching |

That last row matters more than it looks. A large share of dependency CVEs are
not "function X is unsafe". For those, L3 and L4 cannot apply at all, and L2 is
your floor. Say that rather than reporting an empty intersection as good news.

---

## 8. Priority, assembled

Combine the Phoenix evidence with the local evidence. Phoenix owns the left
column. You own the right.

| Exploitation (Phoenix) | Local reachability | Priority |
|---|---|---|
| `cra_actively_exploited: true` | any, including unknown | **P1 — fix now** |
| `ransomware: true` | any | **P1** |
| High severity | Direct, symbol matched (L4) | **P1** |
| High severity | Direct, imported, no symbol match | **P2** |
| High severity | Transitive, imported through a parent | **P2** |
| High severity | Transitive, no first-party import | **P3** |
| Medium or low | Imported | **P3** |
| Medium or low | No first-party import found | **P4 — batch it** |
| Any | Could not determine | **P2 — never P4** |

"Could not determine" outranks "looks unused". An unknown is not a negative.

---

## 9. What the report must always carry

Three sentences, near the top, in the user's own words:

1. Reachability was measured by searching this repository, not by Phoenix.
2. Static search cannot see dynamic or reflective calls, so a low result lowers
   priority and never clears a finding.
3. Every actively-exploited CVE stays P1 regardless of what the search found.
