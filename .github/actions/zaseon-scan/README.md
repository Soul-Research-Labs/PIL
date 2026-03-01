# ZASEON Security Scan — GitHub Action

Automatically scan your Solidity smart contracts for vulnerabilities on every PR and push.

## Quick Start

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  zaseon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Soul-Research-Labs/SOUL/.github/actions/zaseon-scan@main
        with:
          path: contracts/
          fail-on: high
```

## Inputs

| Input                | Default                 | Description                                 |
| -------------------- | ----------------------- | ------------------------------------------- |
| `path`               | `.`                     | Path to Solidity files or project directory |
| `api-key`            | —                       | ZASEON API key for cloud scanning           |
| `api-url`            | `https://api.zaseon.io` | Custom API endpoint                         |
| `severity-threshold` | `medium`                | Minimum severity to report                  |
| `fail-on`            | `high`                  | Severity level that fails the workflow      |
| `format`             | `sarif`                 | Output format (table, json, sarif)          |
| `upload-sarif`       | `true`                  | Upload results to GitHub Advanced Security  |
| `max-findings`       | `50`                    | Maximum findings in the summary             |

## Outputs

| Output           | Description                  |
| ---------------- | ---------------------------- |
| `scan-id`        | Unique scan identifier       |
| `security-score` | Score from 0-100             |
| `total-findings` | Total finding count          |
| `critical-count` | Critical severity count      |
| `high-count`     | High severity count          |
| `sarif-file`     | Path to generated SARIF file |

## SARIF Integration

When `upload-sarif: true` (default), scan results appear in the **Security** tab of your repository, enabling:

- **Code scanning alerts** with inline annotations on PRs
- **Severity filtering** and **dismissal workflows**
- **Trend tracking** across branches

## Advanced Usage

```yaml
- uses: Soul-Research-Labs/SOUL/.github/actions/zaseon-scan@main
  id: scan
  with:
    path: contracts/
    severity-threshold: low
    fail-on: critical
    api-key: ${{ secrets.ZASEON_API_KEY }}

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      const score = '${{ steps.scan.outputs.security-score }}';
      const findings = '${{ steps.scan.outputs.total-findings }}';
      github.rest.issues.createComment({
        ...context.repo,
        issue_number: context.issue.number,
        body: `🛡️ **ZASEON Security Score: ${score}/100** — ${findings} findings`
      });
```
