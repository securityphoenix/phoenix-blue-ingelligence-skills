# Turning a lockfile into purls

Phoenix identifies a component by its package URL. Every call in this skill
needs a list of them.

Format: `pkg:<ecosystem>/<name>@<version>`

---

## 1. The rule that matters most

**Only pinned versions can be assessed.** A range such as `^4.17.0` or `>=2.0`
names many versions with different vulnerability profiles. Skip it, and tell the
user you skipped it.

A lockfile pins. A manifest usually does not. Prefer the lockfile every time.

| Prefer | Over |
|---|---|
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `package.json` |
| `poetry.lock`, `Pipfile.lock`, pinned `requirements.txt` | `pyproject.toml` |
| `Gemfile.lock` | `Gemfile` |
| `go.sum` | `go.mod` |
| `Cargo.lock` | `Cargo.toml` |

---

## 2. Per ecosystem

### npm — `package-lock.json`

Lockfile v2 and v3 use the `packages` object. Keys are paths. Strip the leading
`node_modules/`. Skip the root entry, whose key is `""`.

```
"node_modules/lodash": { "version": "4.17.20" }   ->  pkg:npm/lodash@4.17.20
"node_modules/@babel/core": { "version": "7.1.0" } ->  pkg:npm/@babel/core@7.1.0
```

Keep the `@scope/` prefix. It is part of the name.

Skip any entry with `"dev": true` if the user only wants production. Ask if
unclear.

### npm — `yarn.lock`

Each block starts with one or more descriptors and contains a `version:` line.
Take the name from the descriptor, the version from the line.

### Python — `requirements.txt`

Only `name==version` lines qualify.

```
requests==2.19.0    ->  pkg:pypi/requests@2.19.0
requests>=2.19.0    ->  skip, not pinned
requests            ->  skip, not pinned
-r other.txt        ->  follow the include
```

Normalise the name to lowercase with `-` separators. `Flask_SQLAlchemy` becomes
`flask-sqlalchemy`.

### Python — `poetry.lock`

Each `[[package]]` block has `name` and `version`.

### Go — `go.mod`

Take the `require` block. Keep the `v` prefix on the version.

```
github.com/gin-gonic/gin v1.7.0  ->  pkg:golang/github.com/gin-gonic/gin@v1.7.0
```

Skip lines marked `// indirect` only if the user asks for direct dependencies
only.

### Maven — `pom.xml`

Namespace is `groupId/artifactId`.

```
org.apache.commons : commons-lang3 : 3.9
  ->  pkg:maven/org.apache.commons/commons-lang3@3.9
```

Resolve `${property}` versions from `<properties>` first. If a version cannot be
resolved, skip it and say so.

### Ruby — `Gemfile.lock`

The `specs:` section. Indented entries are `name (version)`.

```
rails (6.0.3)  ->  pkg:gem/rails@6.0.3
```

### Rust — `Cargo.lock`

Each `[[package]]` block has `name` and `version`.

```
pkg:cargo/serde@1.0.130
```

### .NET — `packages.lock.json`

Use the `resolved` version, not `requested`.

```
pkg:nuget/Newtonsoft.Json@12.0.3
```

### PHP — `composer.lock`

The `packages` array. Each has `name` and `version`. Strip a leading `v` only if
the registry does.

```
pkg:composer/monolog/monolog@2.3.5
```

---

## 3. Batching

The server caps a call at **500 purls**. Split larger lists.

- Deduplicate first. Lockfiles repeat transitive dependencies.
- Keep batch order stable so the report is reproducible.
- One call counts as one `batch_lookup` in usage accounting, however many purls
  it carries. Fewer, fuller batches cost less than many small ones.

---

## 4. What to tell the user about skips

Never let a skip disappear. Report it in three buckets:

| Bucket | Meaning |
|---|---|
| Skipped, not pinned | A range, not a version. Cannot be assessed. |
| Skipped, unparseable | Malformed entry or unresolved property. |
| Unresolved by Phoenix | Sent, but the corpus does not know it. |

All three mean **not assessed**. None of them means clean. Say so plainly.
