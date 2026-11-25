# Changelog

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
