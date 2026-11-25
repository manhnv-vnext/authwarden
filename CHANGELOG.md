# Changelog

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
