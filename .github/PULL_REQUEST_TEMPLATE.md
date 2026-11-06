## Description
Provide a brief summary of the changes introduced in this pull request and the motivation behind them.

Fixes #(issue number if applicable)

## Type of Change
- [ ] 🐛 Bug fix (non-breaking change fixing an issue or false positive)
- [ ] 🛡️ New security rule / engine enhancement
- [ ] ⚡ Performance optimization
- [ ] 📝 Documentation update
- [ ] 🧪 Test coverage improvement

## Verification Checklist
- [ ] My code adheres to the project's zero-dependency standard (`dependencies: {}`).
- [ ] I have run local tests with `node --test test/*.test.js` and all tests pass.
- [ ] I have run self-dogfooding scan with `node bin/authwarden.js scan .` without false positives.
- [ ] New rules include test fixtures with both vulnerable and remediated cases.
- [ ] Secrets in test fixtures are mocked/redacted without hardcoding real credentials.
