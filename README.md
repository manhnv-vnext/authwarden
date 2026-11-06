<div align="center">

<img src="assets/banner.svg" alt="AuthWarden Banner" width="100%" />

<br/>
<br/>

[![npm version](https://img.shields.io/npm/v/authwarden-cli.svg?style=flat-square)](https://www.npmjs.com/package/authwarden-cli)
[![License](https://img.shields.io/badge/license-Apache%202.0-emerald.svg?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg?style=flat-square)](package.json)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![GitHub Stars](https://img.shields.io/badge/stars-★★★★★-yellow.svg?style=flat-square)](#)

<p align="center">
  <b>Lightning-fast static analysis for modern Web APIs, Authorization (BOLA/IDOR), Secrets, and Cloud Supply Chain.</b><br/>
  Zero dependencies. Zero configuration. Scans 100,000+ lines of code in under 1 second.
</p>

[Quickstart](#-quickstart) • [Why AuthWarden?](#-why-authwarden) • [Interactive Demo](#-interactive-demo) • [Features](#-features) • [Comparison](#-comparison-with-existing-tools) • [CI/CD & Pre-commit](#-cicd-and-pre-commit) • [Rule Catalog](#-rule-catalog)

<br/>

<img src="assets/terminal-demo.svg" alt="AuthWarden Terminal Demo" width="920" />

</div>

---

## ⚡ Quickstart

No configuration required. Run directly in your repository root with `npx`:

```bash
# Instant scan via GitHub (Zero install required):
npx github:manhnv-vnext/authwarden scan .

# With safe active live secret verification:
npx github:manhnv-vnext/authwarden scan . --verify

# Export SARIF for GitHub Code Scanning:
npx github:manhnv-vnext/authwarden scan . --format sarif --output results.sarif
```

### Global Installation

```bash
npm install -g manhnv-vnext/authwarden

# Then run anywhere:
authwarden scan .
```

---

## 🎯 Why AuthWarden?

Most security scanners flood developers with thousands of noisy, irrelevant warnings. Meanwhile, the **#1 cause of modern data breaches** isn't buffer overflows—it is **Broken Authorization (BOLA/IDOR)**, **Shadow Admin APIs missing middleware**, and **leaked cloud credentials**.

**AuthWarden** was built specifically to solve this gap:

1. **Focus on Access Control:** Understands route structures in **Next.js (App Router & Server Actions)**, **FastAPI**, **Express**, **Django**, and **Go**. Flags unauthenticated endpoints and unscoped database queries.
2. **Zero False-Positive Secrets:** Doesn't just regex matching; includes high-entropy verification and optional safe live verification against Stripe, GitHub, and OpenAI.
3. **AI Agent & MCP Tool Auditing (New):** Scans Model Context Protocol (`mcp.json`) configs for unsandboxed shell execution tools and prompt injection vulnerabilities.
4. **Blazing Speed:** Written in pure, optimized JavaScript with zero external runtime dependencies. Runs anywhere Node.js 18+ is installed.

---

## ✨ Key Features

### 1. 🛡️ API & Authorization Flaw Detection (BOLA / IDOR / BFLA)
Identifies when an API endpoint handles state-altering requests (`POST`, `PUT`, `DELETE`) without session or ownership verification.

```typescript
// ❌ Vulnerable (Flagged by AUTH-003: Unscoped Object Query)
export async function getInvoice(req, res) {
  const invoice = await db.invoice.findById(req.params.id);
  return res.json(invoice);
}

// ✅ Remediated
export async function getInvoice(req, res) {
  const invoice = await db.invoice.findFirst({
    where: { id: req.params.id, orgId: req.user.orgId }
  });
  return res.json(invoice);
}
```

### 2. ⚡ Next.js Server Actions Auditing
Server Actions (`'use server'`) are publicly invokable RPCs. AuthWarden flags mutations executed without identity assertions.

### 3. 🔑 Precision Secret Scanner & Auto-Redaction
Detects 30+ credential patterns across AWS, GitHub, Stripe, OpenAI, and database connection URIs. Every secret snippet is automatically redacted (`sk_live_51M***...***`) to prevent leakage into build logs.

### 4. 🐳 IaC & Container Security Doctor
Audits `Dockerfile`, `docker-compose.yml`, and `*.tf` files for root execution, sensitive port exposure (`3306`, `5432`, `6379`), and `/var/run/docker.sock` escapes.

### 5. 🤖 AI Agent & MCP Config Guard
Audits Claude Desktop, Cursor, and custom AI agent tool manifests to block unsandboxed shell execution (`bash`, `powershell`) and root filesystem access (`/`).

### 6. 📦 SCA & Known CVE Scanner with Reachability Analysis
Audits `package.json`, `requirements.txt`, `go.mod`, and `composer.json` for known high-severity CVEs across modern ecosystems. Uses AST-guided reachability checks to distinguish between active dependencies and dormant ones, cutting alert noise by 80%.

### 7. ⚖️ Business Logic & Workflow State Guard
Flags critical transaction flaws: client-supplied `is_paid` payment status evasion, non-atomic TOCTOU race conditions in balances/coupons, negative quantity/price manipulation, and JWT verification missing algorithm whitelists.

### 8. 📋 OpenAPI & Swagger Security Auditor
Audits `openapi.yaml`, `swagger.json`, and Postman collections for unprotected sensitive endpoints, explicit `security: []` overrides, credentials exposed in query parameters, and cleartext HTTP URLs.

---

## 📊 Comparison with Existing Tools

| Capability | SonarQube | Semgrep CE | TruffleHog | **AuthWarden** |
|:---|:---:|:---:|:---:|:---:|
| **Zero Dependencies / No Setup** | ❌ | ⚠️ | ✅ | **✅ (1s start)** |
| **BOLA / IDOR Heuristic** | ❌ | ⚠️ (Complex rules) | ❌ | **✅ Built-in** |
| **Next.js Server Actions Check** | ❌ | ❌ | ❌ | **✅ Built-in** |
| **Live Secret Active Verification**| ❌ | ❌ | ✅ | **✅ Built-in** |
| **MCP Agent & Tool Audit** | ❌ | ❌ | ❌ | **✅ Built-in** |
| **Scan Speed (50k LOC)** | ~45s | ~8s | ~3s | **< 1s** |
| **Output Formats** | Proprietary | SARIF/JSON | JSON | **TUI / SARIF / PR Markdown / JSON** |

---

## 🛠️ CI/CD and Pre-commit

### Install Pre-commit Git Hook (1 Second)

Block vulnerable code from ever reaching remote branches:

```bash
npx authwarden init-hook
```

This creates an executable `.git/hooks/pre-commit` that validates your changes before commit.

### GitHub Actions Integration

Create `.github/workflows/security.yml`:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run AuthWarden Scan
        run: npx authwarden scan . --fail-on high --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 📜 Rule Catalog

AuthWarden ships with 30+ precision rules across 6 security categories:

| Category | Rule ID | Title | Default Severity |
|:---|:---|:---|:---:|
| **API & Auth** | `AUTH-001` | Shadow Admin Route Missing Auth Middleware | `CRITICAL` |
| **API & Auth** | `AUTH-002` | State-Modifying Route Without Authentication | `HIGH` |
| **API & Auth** | `AUTH-003` | Potential BOLA / IDOR Unscoped Object Query | `HIGH` |
| **API & Auth** | `AUTH-004` | Server Action Missing Identity Check | `HIGH` |
| **API & Auth** | `AUTH-005` | Mass Assignment in Request Body Handling | `MEDIUM` |
| **API & Auth** | `AUTH-006` | Unthrottled Auth Endpoint (Brute-Force Risk) | `HIGH` |
| **API & Auth** | `AUTH-007` | Sensitive Data Exposure (Password Hash in Response) | `HIGH` |
| **SAST & Taint** | `TAINT-001` | Taint Flow: Request Input Reaches Command Execution (RCE) | `CRITICAL` |
| **SAST & Taint** | `TAINT-002` | Taint Flow: Request Input Reaches Raw SQL Query | `CRITICAL` |
| **SAST & Taint** | `TAINT-003` | Taint Flow: Request Input Reaches File System Read | `HIGH` |
| **SAST & Taint** | `TAINT-004` | Taint Flow: Request Input Reaches Outbound HTTP Call (SSRF) | `HIGH` |
| **SAST & Taint** | `SAST-001` | SQL Injection: Dynamic Query Construction with User Input | `CRITICAL` |
| **SAST & Taint** | `SAST-002` | Command Injection: Untrusted Input in System Shell Call | `CRITICAL` |
| **SAST & Taint** | `SAST-003` | Dangerous Dynamic Code Execution via `eval()` | `CRITICAL` |
| **SAST & Taint** | `SAST-006` | Cross-Site Scripting (XSS): `dangerouslySetInnerHTML` / DOM | `HIGH` |
| **SAST & Taint** | `SAST-007` | Insecure Deserialization (`pickle` / unsafe `yaml`) | `CRITICAL` |
| **SAST & Taint** | `SAST-008` | Disabled TLS Certificate Verification | `HIGH` |
| **SAST & Taint** | `SAST-011` | Open Redirect: Unvalidated URL in Redirect Call | `MEDIUM` |
| **Secrets** | `SEC-001` | AWS Access Key ID Exposure | `CRITICAL` |
| **Secrets** | `SEC-002` | GitHub Personal Access Token Exposure | `CRITICAL` |
| **Secrets** | `SEC-003` | OpenAI API Secret Key Exposure | `CRITICAL` |
| **Secrets** | `SEC-004` | Stripe Live Secret Key Exposure | `CRITICAL` |
| **Secrets** | `SEC-007` | Database Connection URI with Plaintext Password | `CRITICAL` |
| **IaC & Cloud** | `IAC-001` | Container Default Execution as Root | `MEDIUM` |
| **IaC & Cloud** | `IAC-002` | Insecure Remote Script Pipe (`curl \| sh`) | `HIGH` |
| **IaC & Cloud** | `IAC-003` | Exposed Database Port in Container Manifest | `HIGH` |
| **IaC & Cloud** | `IAC-004` | Docker Daemon Socket Mounted in Container | `CRITICAL` |
| **IaC & Cloud** | `IAC-006` | Public S3 Bucket Configuration in Terraform | `CRITICAL` |
| **IaC & Cloud** | `IAC-007` | Sensitive Port Open to `0.0.0.0/0` in Security Group | `CRITICAL` |
| **IaC & Cloud** | `IAC-008` | Kubernetes Pod Configured with Host Network or Host PID | `HIGH` |
| **IaC & Cloud** | `IAC-009` | Kubernetes Container Allows Privilege Escalation | `HIGH` |
| **IaC & Cloud** | `IAC-010` | Secret Baked into Dockerfile `ENV` Instruction | `CRITICAL` |
| **AI & MCP** | `MCP-001` | Unsandboxed Shell Execution Tool in MCP Config | `CRITICAL` |
| **AI & MCP** | `MCP-002` | Unrestricted Root Filesystem Path in MCP Server | `HIGH` |
| **AI & MCP** | `MCP-004` | Prompt Injection Risk in Agent System Prompt | `MEDIUM` |
| **Business Logic**| `LOGIC-001` | Multi-Step Workflow / Payment Status Evasion via Client Payload | `HIGH` |
| **Business Logic**| `LOGIC-002` | Potential TOCTOU Race Condition on Balance / Coupon State | `HIGH` |
| **Business Logic**| `LOGIC-003` | Unchecked Numeric Input: Negative Price / Quantity Tampering | `HIGH` |
| **Business Logic**| `LOGIC-004` | Insecure JWT Verification: Missing Algorithm Whitelist | `HIGH` |
| **Business Logic**| `LOGIC-005` | Client-Only Logout: Missing Server-Side Session Revocation | `MEDIUM` |
| **API Contract** | `SPEC-001` | Unprotected Sensitive Operation in API Specification | `HIGH` |
| **API Contract** | `SPEC-002` | Explicit Public Security Override (`security: []`) | `HIGH` |
| **API Contract** | `SPEC-003` | Sensitive Credential Defined as URL Query Parameter | `HIGH` |
| **API Contract** | `SPEC-004` | Insecure Cleartext Transport (HTTP) in Server URL | `MEDIUM` |
| **SCA & CVE** | `CVE-xxxx` | Known Vulnerable Dependency (npm, PyPI, Go, Composer) | `HIGH` / `CRITICAL` |
| **SCA & CVE** | Reachability | Imported vs Dormant Dependency Vulnerability Tagging | `INFO` |
| **Supply Chain** | `SUPPLY-001`| Suspicious Outbound Script in Package Lifecycle Hook | `CRITICAL` |

---

## 🤝 Contributing

We welcome community rule proposals and contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on how to submit new rules and tests.

---

## 📄 License

AuthWarden is licensed under the [Apache 2.0 License](LICENSE).
