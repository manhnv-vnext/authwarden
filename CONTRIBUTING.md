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
   - `src/engines/mcpAgentScanner.js`: AI agent configs, MCP tool permissions.

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

3. **Add a unit test in `test/`** to ensure your rule fires on vulnerable code and ignores safe patterns.

4. **Run the test suite:**
   ```bash
   npm test
   ```

5. **Submit a Pull Request** with a brief description and link to any relevant CVE or OWASP category!

---

## 📜 Code of Conduct

AuthWarden is committed to providing a welcoming, inclusive, and harassment-free environment for all contributors.
