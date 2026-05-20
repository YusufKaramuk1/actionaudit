# Examples

Sample workflows for trying ActionAudit.

- **`vulnerable-ci.yml`** — intentionally insecure; triggers several rules.
  Do not copy it into a real repository.
- **`safe-ci.yml`** — the secure counterpart; passes every rule.

Try them:

```bash
actionaudit scan examples/vulnerable-ci.yml
actionaudit scan examples/safe-ci.yml
actionaudit scan examples/vulnerable-ci.yml --format html --output report.html
```
