# Contributing to AuthWarden 🛡️

We welcome all contributions! Whether it's adding new vulnerability rules, improving framework detection, or reporting edge cases, your help makes open-source software more secure.

---

## 🚀 How to Add a New Rule

Adding a new rule is straightforward:

1. **Pick the relevant engine:**
   - `src/engines/apiAuthScanner.js`: Route authorization, IDOR/BOLA, shadow routes.
   - `src/engines/secretScanner.js`: High-entropy tokens, credentials, keys.
   - `src/engines/iacScanner.js`: Dockerfile, Docker Compose, Terraform misconfigurations.
   - `src/engines/supplyChainScanner.js`: Malicious scripts, package integrity.
   - `src/engines/mcpAgentScanner.js`: AI agent configs, MCP tool permissions, tool poisoning.
   - `src/engines/sastScanner.js`: Injection, SSRF, path traversal and intra-file taint flows.
   - `src/engines/businessLogicScanner.js`: Workflow, race-condition and JWT logic flaws.
   - `src/engines/apiSpecScanner.js`: OpenAPI / Swagger / Postman contracts.
   - `src/engines/cveScanner.js` and `src/engines/osvScanner.js`: Offline CVE list and opt-in OSV.dev lookup.
   - `src/engines/authContext.js`: Project-wide auth guards (middleware, fallback policies).

   Read files through `src/utils/fileContext.js` (`readText`, `getLines`, `getCodeLines`) so content is loaded once per scan and comments are stripped consistently.

2. **Add a rule entry:**
   Each finding follows this clean format:
   ```javascript
   findings.push({
     ruleId: 'AUTH-006',
     severity: 'HIGH', // CRITICAL | HIGH | MEDIUM | LOW
     title: 'Descriptive Rule Title',
     file: relPath,
     line: lineNumber,
     snippet: codeSnippet,
     description: 'Explain what vulnerability pattern was found and why it is dangerous.',
     remediation: 'Provide actionable code advice on how to fix it.'
   });
   ```

3. **Register the rule in `src/rules/catalog.js`** (category, severity, confidence, CWE) and add a row to the README rule table. `test/catalog.test.js` fails if the engine, catalog and README disagree.

4. **Add a unit test in `test/`** to ensure your rule fires on vulnerable code and ignores safe patterns.

5. **Run the test suite:**
   ```bash
   npm test
   ```

6. **Submit a Pull Request** with a brief description and link to any relevant CVE or OWASP category!

---

## 📜 Code of Conduct

AuthWarden is committed to providing a welcoming, inclusive, and harassment-free environment for all contributors.
