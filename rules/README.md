# AuthWarden Custom Rules 🛡️

Place custom JSON rule files in this directory (`rules/*.json`). AuthWarden automatically detects and executes them during each scan.

### Example Schema (`rules/company-rules.json`):

```json
[
  {
    "id": "CORP-001",
    "name": "Banned Legacy Logger",
    "severity": "HIGH",
    "languages": [".js", ".ts"],
    "pattern": "console\\.log\\(",
    "description": "Production code should use the enterprise structured logger instead of console.log.",
    "remediation": "Replace with `logger.info()` from `@corp/logging`."
  }
]
```

### Supported Properties:
- `id` *(string, required)*: Unique rule identifier (e.g. `CORP-001`).
- `name` *(string, required)*: Concise finding title.
- `severity` *(string, optional)*: `CRITICAL` | `HIGH` (default) | `MEDIUM` | `LOW`.
- `pattern` *(string, required)*: Regular expression string to search for in source lines.
- `languages` *(array of strings, optional)*: File extensions to restrict scanning (e.g. `[".js", ".py"]`). If omitted, scans all text files.
- `description` *(string, optional)*: Detail about the violation.
- `remediation` *(string, optional)*: Guidance on how developers can remediate.
