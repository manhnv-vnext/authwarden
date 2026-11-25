# Changelog

## 1.9.0

This release follows an independent review of 1.8.0 and a run against eight public projects. Most of it makes the tool safer to rely on rather than adding features.

### Security
- A config file inside the scanned directory can no longer set `output` (arbitrary file write), `watch` (hang) or `verify` / `online` (network access). These are accepted only on the command line or through `--config`.
- New `--untrusted` mode for pull requests from forks: ignores the repository's config, custom rules, inline suppressions and `.gitignore`.
- Custom rules run in a worker thread with a time limit, so a catastrophic regex cannot hang the scan; rule ids and severities are validated, and one invalid rule no longer drops the others.
- HTML report: a custom rule's `severity` could inject markup. Markdown report and `$GITHUB_STEP_SUMMARY`: snippet, file name and title could break out of their context. Both are escaped now.
- Secret snippets leaked in JSON, Markdown and baseline files: only the first occurrence of one secret per line was masked, private key bodies on one line were printed, and short connection-string passwords stayed visible. Every secret on a line is masked now.
- Symbolic links are no longer followed (they could pull files from outside the scanned tree into the report).

### Fixed: routes wrongly reported as protected
- Auth detection matched loose substrings (`auth`, `token`, `session`, `protect`, `security`) in raw text, so a CORS origin string, `csrfProtection`, a variable named `author`, a word in the route path or a TODO comment made a route "protected". It now requires an auth identifier in real code: comments and string contents are removed first.
- The comment stripper treated `/*` inside a regex literal as a block comment, hiding the rest of the file, and a backtick in a regex literal as a template string. Source masking was rewritten to understand regex literals, template literals, Python docstrings and C# verbatim strings.
- Next.js: `export function GET` and `export const POST = ...` handlers were not discovered; a handler's auth check no longer leaks into the next handler; a middleware that only mentions auth in a comment no longer protects routes.
- FastAPI: only the decorator arguments and the function parameters are examined, and annotated dependencies (`current_user: CurrentUser`) are recognised.
- ASP.NET Core: commented-out fallback policies are ignored; a policy in one project no longer protects another; `.AllowAnonymous()` after a lambda with statements is honoured; each controller class in a file gets its own attributes and route; endpoints mapped by an extension method chained with `.RequireAuthorization()` are recognised.
- Spring: `permitAll()` matchers are excluded from the global `authenticated()` rule; mappings with named attributes and package-private methods are discovered.
- Express: a router mounted both publicly and behind auth is no longer treated as protected; Express route detection no longer runs on Python files.

### Fixed: other
- `--staged` scanned nothing when the target was a subdirectory, scanned the working tree instead of the staged content, and skipped non-ASCII file names. It now scans a snapshot of the git index.
- Offline SCA missed: single-line `require` in `go.mod`, extras and spaces in `requirements.txt`, Maven versions set through properties, NuGet `Version` on a following line or as a child element, pnpm v5 keys, yarn aliases and `composer.lock`. It over-reported `package.json` ranges when a lockfile resolved a fixed version, and truncated Go pseudo-versions. Manifest parsing is now shared with the OSV.dev lookup.
- `SAST-001` fired on the word "delete" next to request input; it now requires SQL statement shape. `SAST-004` fired on any variable named `url` or `uri`; it now requires request input or a name that says the value comes from outside.
- `AUTH-003` fired on repository method declarations.
- A `.gitignore` line `*` disabled the scan. Inline suppression matched the marker anywhere on the line, including inside a string; it now has to be in a comment.
- In test and example files, the words "fake", "dummy" or "placeholder" anywhere in the file suppressed every secret in it; now only the line that says so is skipped.
- CLI: unknown `--format` / `--fail-on` values and a missing `--config` file are errors (exit 2) instead of silent fallbacks; a config file containing `null` no longer crashes; `init-hook` no longer overwrites an existing hook and the hook runs this tool from its GitHub source.

### Added
- Route state `unknown` (middleware present but not recognised as auth) and the `authIdentifiers` config option to name project-specific auth middleware. Findings on such routes carry `confidence: LOW`.
- Suppression counts (`stats.suppressed`) and scan warnings (`stats.warnings`) in every report.
- 19 corpus cases taken from the review and from real projects (89 in total).

### Changed (may affect existing users)
- Expect more `AUTH-001` findings where an earlier version accepted a loosely matching word as auth, and fewer where auth is declared one level up.
- `routes[].auth` can be `unknown`; `stats.routes` gains an `unknown` count.
- Baseline fingerprints of `SEC-007` and `SEC-008` findings change because their snippets are masked differently; regenerate baselines that contain them.
- README no longer claims Django or Go route support, which never existed.

## 1.8.0

### Fixed
- Offline CVE database was hand-written with a single "fixed version" per entry; checked against OSV.dev, 25 of 30 entries had wrong ranges or did not exist for that package (for example lodash 4.17.20 was reported for CVE-2020-8203, fixed in 4.17.19). It is now a generated OSV.dev snapshot (`src/data/cve-db.json`, 684 advisories for 31 packages) matched by real affected ranges, and one package version can report several advisories. Severities now come from the advisory.
- Piped output larger than the pipe buffer was truncated (`authwarden scan . --format json | jq`) because the process exited before stdout flushed.
- Express route analysis treated the handler as middleware, so a handler named `sessionHandler.x` or `authController.y` made the route look protected. Only arguments between the path and the handler count now, plus wrapper calls such as `requireAuth(handler)`.
- Commented-out Express routes and route-looking text inside string literals were listed as routes.
- `isLoggedIn` / `ensureLoggedIn` / `login_required` and deny-all guards were not recognised as auth.
- `AUTH-003` no longer flags lookups keyed by the caller's own identity (`findByPk(loggedInUser.data.id)`).
- `SEC-007` no longer flags connection strings whose password is a template placeholder.
- `TAINT-002` no longer flags a tainted value passed as a bound parameter next to a literal SQL string.
- `SAST-004` no longer flags calls to a configured or constant URL with no request input on the line.

### Added
- `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5 to v9) and `poetry.lock` support, offline and with `--online`.
- Fastify routes and `addHook` auth guards in the route inventory.
- Cross-file Express guards: a router module mounted behind auth (`app.use(requireAuth); app.use(adminRouter)`) is treated as protected.
- Auth checks inside an inline handler body (`if (!req.user?.isAdmin) return res.sendStatus(403)`).
- `AUTH-003` covers Prisma `findUnique` / `findFirst` by id; `LOGIC-004` covers `jwt.verify(token, process.env.SECRET)`.
- `npm run bench`: labelled regression corpus (70 cases) with per-rule precision and recall; `npm test` fails when a case changes outcome.
- `npm run update-cve-db`: regenerates the offline snapshot from OSV.dev.

### Changed
- Projects with outdated dependencies will see more SCA findings than before, because every advisory for an affected version is reported instead of one per package.

## 1.7.0

### Security
- Raw secret values are no longer written to JSON reports. `rawSecret` is kept in memory only for `--verify`, and verification results are attached to the finding instead of a map keyed by the secret.

### Added
- `authwarden routes [path]`: route inventory listing every discovered endpoint, whether auth was detected, and the evidence. Also available as `routes` and `stats.routes` in JSON output.
- Upstream auth detection, removing a large class of false positives: Express `router.use(auth)` / `app.use('/prefix', auth)`, Next.js `middleware.ts` (including `matcher` patterns), FastAPI router `dependencies`, ASP.NET Core fallback policy and `MapControllers().RequireAuthorization()`, Spring `SecurityFilterChain` with `anyRequest().authenticated()`.
- FastAPI `APIRouter(prefix=...)` is applied to route paths, so admin routers are recognised.
- `--online`: opt-in lookup of pinned dependency versions on OSV.dev (npm, PyPI, Go, Maven, NuGet, Packagist). Sends only ecosystem, package name and version. Off by default.
- `MCP-005`: hidden, model-directed instructions in MCP tool descriptions (tool poisoning).
- `allowSecrets` config option: regex allowlist for known non-sensitive keys.
- Every finding carries `confidence`, `cwe` and `category` from a central rule catalog (`src/rules/catalog.js`).
- SARIF: CWE tags, `security-severity`, `precision`, `helpUri` and line-independent `partialFingerprints`.

### Fixed
- Business-logic and BOLA rules skipped any line containing `//`, including lines with a URL or a trailing comment. Rules now run on comment-stripped code.
- Test-directory detection matched substrings, so code under `latest/` or `contest/` was skipped. It now matches path segments.
- Spring scanner reported the controller class itself as an endpoint when it had a class-level `@RequestMapping`.
- MCP findings were always reported at line 1; they now point at the offending line, and secret values are redacted in the snippet.
- Version string was hardcoded in several files; it is now read from `package.json`.

### Changed
- README claims aligned with the implementation: reachability is described as an import-level check, unverified speed and noise-reduction figures were removed, and the comparison table states that matching is pattern-based.
- Files are read once per scan and shared between engines.
- `verifiedMap` was removed from the scan result; use `finding.verification`.
