# audit-gate

A GitHub Action that runs JFrog CLI security audits on your source code and publishes rich, actionable results directly in your GitHub workflow's **Job Summary**.

Supports SCA (CVEs), Secrets detection, IaC misconfiguration, SAST, and policy-based violations — all in one step.

> **Prerequisites:** JFrog CLI must be installed and configured before using this action.
> Add [`jfrog/setup-jfrog-cli`](https://github.com/jfrog/setup-jfrog-cli) as a step before `audit-gate`.

📖 [JFrog Security Scan Docs](https://docs.jfrog.com/security/docs/scan-your-source-code)

---

## Quick Start

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Install and configure JFrog CLI (required)
      - uses: jfrog/setup-jfrog-cli@v4
        env:
          JF_URL: ${{ secrets.JF_URL }}
          JF_ACCESS_TOKEN: ${{ secrets.JF_ACCESS_TOKEN }}

      # Run the security audit
      - uses: jfrog/audit-gate@v1
        with:
          fail: 'true'
```

---

## Examples

### Run all scans (default)

```yaml
- uses: jfrog/audit-gate@v1
```

When no scan-type flags are set, all available scans run (SCA, Secrets, IaC, SAST).

### Selective scans

```yaml
- uses: jfrog/audit-gate@v1
  with:
    sca: 'true'
    secrets: 'true'
```

### With Xray policy scope

```yaml
- uses: jfrog/audit-gate@v1
  with:
    project: 'my-project-key'
    fail: 'true'
```

When `project`, `watches`, or `repo-path` is set, the results show **policy violations** from that scope. Vulnerabilities outside the policy are hidden unless `vuln: 'true'` is also set.

### Use static SCA engine (enhanced accuracy)

```yaml
- uses: jfrog/audit-gate@v1
  with:
    static-sca: 'true'
    snippet: 'true'    # Include code snippets (requires CLI v2.94.0+)
```

### Use outputs in later steps

```yaml
- uses: jfrog/audit-gate@v1
  id: audit
  with:
    fail: 'false'   # Don't fail — let us handle it below

- name: Report results
  run: |
    echo "Result: ${{ steps.audit.outputs.result }}"
    echo "Vulnerabilities: ${{ steps.audit.outputs.vulnerabilities-count }}"
    echo "Critical: ${{ steps.audit.outputs.critical-count }}"

- name: Fail if critical issues found
  if: steps.audit.outputs.critical-count > 0
  run: exit 1
```

### Force plain audit (no git context)

```yaml
- uses: jfrog/audit-gate@v1
  with:
    force-no-git: 'true'
```

---

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `working-dirs` | No | — | Comma-separated list of relative directories to audit. Defaults to the repository root. |
| `exclusions` | No | — | Semicolon-separated exclusion patterns (supports `*` and `?`). Example: `*node_modules*;*test*` |
| `project` | No | — | JFrog project key for Xray policy resolution. Incompatible with `watches` and `repo-path`. |
| `watches` | No | — | Comma-separated Xray watch names for policy violations. Incompatible with `project` and `repo-path`. |
| `repo-path` | No | — | Artifactory repository path for Xray policy resolution. Incompatible with `project` and `watches`. |
| `vuln` | No | `false` | Show all vulnerabilities regardless of policy (useful alongside `project`/`watches`/`repo-path`). |
| `threads` | No | `5` | Number of parallel scan threads. |
| `fail` | No | `true` | Fail the action when any finding is detected (vulnerabilities, violations, secrets, IaC, SAST). |
| `fail-on-pr-policy` | No | `true` | Fail when any violation has "Fail Pull Request" configured in the Xray policy (independent of `fail`). |
| `fail-on-build-policy` | No | `true` | Fail when any violation has "Fail Build" configured in the Xray policy (independent of `fail`). |
| `sca` | No | `false` | Run Software Composition Analysis only. |
| `secrets` | No | `false` | Run secrets detection only. |
| `sast` | No | `false` | Run SAST only. |
| `iac` | No | `false` | Run IaC misconfiguration scan only. |
| `static-sca` | No | `false` | Use the new static SCA engine (requires CLI >= v2.90.0). |
| `snippet` | No | `false` | Include code snippets in static SCA results (requires `static-sca: true` and CLI >= v2.94.0). |
| `licenses` | No | `false` | Include discovered open-source licenses in results. |
| `force-no-git` | No | `false` | Force `jf audit` instead of `jf git audit` (skips git context detection). |

> **Scan type flags:** When none of `sca`, `secrets`, `sast`, `iac` are `true`, all sub-scans run. When at least one is `true`, only the selected scans run.

---

## Outputs

| Output | Description |
|---|---|
| `result` | `pass` or `fail` |
| `vulnerabilities-count` | Total SCA vulnerabilities |
| `violations-count` | Total policy violations (security + license + operational risk) |
| `secrets-count` | Total secrets (vulnerabilities + violations) |
| `iac-count` | Total IaC issues (vulnerabilities + violations) |
| `sast-count` | Total SAST issues (vulnerabilities + violations) |
| `license-violations-count` | Total license policy violations |
| `operational-risk-count` | Total operational risk violations |
| `critical-count` | Critical severity findings across all scan types |
| `high-count` | High severity findings across all scan types |
| `scan-id` | JFrog `multiScanId` — links to the Platform scan results |
| `has-errors` | `true` if any scan errors occurred |
| `pr-policy-fail` | `true` if any violation has the "Fail Pull Request" policy rule |
| `build-policy-fail` | `true` if any violation has the "Fail Build" policy rule |

---

## Job Summary

The action generates a rich Job Summary visible directly in GitHub's workflow run page.

**When findings are detected:**
- Overview table with counts per scan type and severity
- Collapsible sections for each finding category (SCA, Secrets, IaC, SAST, Violations)
- Severity icons with contextual analysis (Applicable / Not Applicable) indicators
- Direct dependency chain for SCA findings
- Watch and policy information for violations
- Prominent error section when scans encounter issues

**When no findings are detected:**
- Clear "No security issues detected" confirmation

**Scan status table:**
- Shown at the top of the summary if any sub-scan failed
- Shown at the bottom if all scans succeeded

---

## CLI Version Requirements

| Feature | Minimum CLI Version |
|---|---|
| Core audit (`jf git audit`) | v2.90.0 |
| `static-sca` flag | v2.90.0 |
| `snippet` flag | v2.94.0 |

Use [`jfrog/setup-jfrog-cli`](https://github.com/jfrog/setup-jfrog-cli) to install a specific CLI version:

```yaml
- uses: jfrog/setup-jfrog-cli@v4
  with:
    version: '2.94.0'
  env:
    JF_URL: ${{ secrets.JF_URL }}
    JF_ACCESS_TOKEN: ${{ secrets.JF_ACCESS_TOKEN }}
```

---

## Failure Behavior

The action supports three independent fail conditions — any one of them can trigger failure:

| Condition | Input | Default | Triggers when |
|---|---|---|---|
| Any finding | `fail` | `true` | At least one vulnerability, violation, secret, IaC, or SAST issue found |
| PR policy | `fail-on-pr-policy` | `true` | Any violation has "Fail Pull Request" configured in the Xray policy |
| Build policy | `fail-on-build-policy` | `true` | Any violation has "Fail Build" configured in the Xray policy |

All three conditions are evaluated independently. The action **always shows all findings** regardless of which conditions are enabled.

Policy conditions (`fail-on-pr-policy`, `fail-on-build-policy`) are most useful when a policy scope (`project`, `watches`, or `repo-path`) is configured — they let Xray policy rules drive workflow failure directly.

To use the step outputs to control failure manually:

```yaml
- uses: jfrog/audit-gate@v1
  id: audit
  with:
    fail: 'false'
    fail-on-pr-policy: 'false'
    fail-on-build-policy: 'false'

- if: steps.audit.outputs.critical-count > 0
  run: |
    echo "Critical issues detected — failing!"
    exit 1
```

---

## Custom Resource Location (GitHub Enterprise / Private Servers)

The action's job summary uses severity icon images hosted in this action's repository.
The image URL is resolved automatically:

- **Remote usage** (`uses: owner/audit-gate@v1`): images are served from the exact version of
  the action being used (`GITHUB_ACTION_REPOSITORY` + `GITHUB_ACTION_REF`)
- **Local testing** (`uses: ./`): images are served from the current repository at the current
  commit SHA — valid after code is merged and pushed

`GITHUB_SERVER_URL` is used as the base URL, so **GitHub Enterprise Server** is supported
out of the box — images are served from your GHES instance automatically.

**If images do not appear** (e.g., the action repository is private or you're on an air-gapped
environment), host the `resources/v2/` directory on any reachable HTTP server and update the
`getResourcesBaseUrl` function in `src/summary.ts` to point to your custom URL before building.

