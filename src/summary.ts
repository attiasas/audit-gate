import * as core from '@actions/core';
import {
  ActionInputs,
  ComponentRow,
  FindingCounts,
  LicenseRow,
  LicenseViolationRow,
  OperationalRiskViolationRow,
  ScanStatus,
  SimpleJsonResults,
  SourceCodeRow,
  VulnerabilityOrViolationRow,
  hasPolicyScope,
} from './types';

// ---------------------------------------------------------------------------
// Resource image URLs
// ---------------------------------------------------------------------------

/**
 * Base URL for severity icon images bundled with this action's repository.
 *
 * Resolution order (no external fallback — always points to this action's own repo):
 * 1. GITHUB_ACTION_REPOSITORY + GITHUB_ACTION_REF — set when using the action remotely
 *    (e.g. `uses: owner/audit-gate@v1`). Points to the exact version in use.
 * 2. GITHUB_REPOSITORY + GITHUB_SHA — fallback for local testing (`uses: ./`).
 *    Points to the current repo at the current commit, valid after code is merged and pushed.
 *
 * GITHUB_SERVER_URL handles GitHub Enterprise Server automatically — images are
 * served from your GHES instance with no extra configuration.
 */
function getResourcesBaseUrl(): string {
  const serverUrl = process.env.GITHUB_SERVER_URL ?? 'https://github.com';
  // Remote action usage: GITHUB_ACTION_REPOSITORY is set (e.g. "owner/audit-gate")
  // Local testing (uses: ./): fall back to the current repo + commit SHA
  const repo = process.env.GITHUB_ACTION_REPOSITORY ?? process.env.GITHUB_REPOSITORY ?? '';
  const ref = process.env.GITHUB_ACTION_REF ?? process.env.GITHUB_SHA ?? 'main';
  return `${serverUrl}/${repo}/raw/${ref}/resources/v2/`;
}

// ---------------------------------------------------------------------------
// Severity ordering and helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 99,
};

const SEVERITY_LABELS: string[] = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];

function severityRank(severity?: string): number {
  return SEVERITY_ORDER[(severity ?? '').toLowerCase()] ?? 99;
}

/** Is the row "Not Applicable" (contextual analysis determined it is not exploitable)? */
function isNotApplicable(applicable?: string): boolean {
  return (applicable ?? '').toLowerCase() === 'not applicable';
}

/**
 * Two-level sort:
 * 1. By severity (Critical → High → Medium → Low → Unknown)
 * 2. Within each severity, "Not Applicable" rows go to the bottom
 */
export function sortFindings<T extends { severity?: string; applicable?: string }>(
  rows: T[],
): T[] {
  return [...rows].sort((a, b) => {
    const severityDiff = severityRank(a.severity) - severityRank(b.severity);
    if (severityDiff !== 0) return severityDiff;
    const aNA = isNotApplicable(a.applicable) ? 1 : 0;
    const bNA = isNotApplicable(b.applicable) ? 1 : 0;
    return aNA - bNA;
  });
}

/** Sort source code rows: severity → file name (alphabetical) → start line (ascending) */
function sortSourceRows(rows: SourceCodeRow[]): SourceCodeRow[] {
  return [...rows].sort((a, b) => {
    const severityDiff = severityRank(a.severity) - severityRank(b.severity);
    if (severityDiff !== 0) return severityDiff;
    const fileDiff = (a.file ?? '').localeCompare(b.file ?? '');
    if (fileDiff !== 0) return fileDiff;
    return (a.startLine ?? 0) - (b.startLine ?? 0);
  });
}

/** Count findings by severity label */
export function countBySeverity(
  rows: Array<{ severity?: string }>,
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of rows) {
    const key = capitalize(row.severity ?? 'Unknown');
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

/** Escape special HTML characters to prevent XSS in the job summary */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Truncate a string to max characters, appending ellipsis if needed */
export function truncate(s: string, max = 150): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + '…';
}

function capitalize(s: string): string {
  if (!s) return '';
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

/** Build an HTML table compatible with GitHub job summary rendering */
export function htmlTable(headers: string[], rows: string[][]): string {
  if (rows.length === 0) return '<p><em>No items found.</em></p>';
  const thead = `<thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>`;
  const tbody = `<tbody>${rows
    .map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join('')}</tr>`)
    .join('')}</tbody>`;
  return `<table>${thead}${tbody}</table>`;
}

/** Wrap content in a collapsible <details> block */
function details(summary: string, content: string): string {
  return `<details>\n<summary>${summary}</summary>\n\n${content}\n</details>`;
}

// ---------------------------------------------------------------------------
// Severity icon rendering
// ---------------------------------------------------------------------------

/**
 * Return an HTML img tag for the severity icon.
 * Uses "Not Applicable" variant (greyed out) when applicable === "Not Applicable",
 * and the regular coloured icon for all other statuses.
 */
export function severityIcon(severity?: string, applicable?: string): string {
  const base = getResourcesBaseUrl();
  const sev = capitalize(severity ?? 'Unknown');
  const notApplicable = isNotApplicable(applicable);

  let filename: string;
  let alt: string;
  if (notApplicable) {
    filename = `notApplicable${sev}.png`;
    alt = `${sev} (Not Applicable)`;
  } else {
    filename = `applicable${sev}Severity.png`;
    alt = sev;
  }

  return `<img src="${base}${filename}" alt="${alt}" width="20"/>`;
}

/** Return an HTML img tag for the small SVG severity badge used in overview headers */
export function smallSeverityBadge(severity: string): string {
  const base = getResourcesBaseUrl();
  const sev = capitalize(severity);
  return `<img src="${base}small${sev}.svg" alt="${sev}" width="16"/>`;
}

/** Render a severity cell: icon + label */
function severityCell(severity?: string, applicable?: string): string {
  const icon = severityIcon(severity, applicable);
  const label = escapeHtml(capitalize(severity ?? 'Unknown'));
  const notApplicable = isNotApplicable(applicable);
  const suffix = notApplicable ? ' <em>(NA)</em>' : '';
  return `${icon} ${label}${suffix}`;
}

// ---------------------------------------------------------------------------
// Component / dependency helpers
// ---------------------------------------------------------------------------

/**
 * Format the components[] list as a comma-separated "name@version" string.
 * Components are the DIRECT importers of the impacted package (may be multiple).
 */
export function formatDirectDeps(components?: ComponentRow[]): string {
  if (!components || components.length === 0) return '—';
  return components
    .map(c => {
      const name = escapeHtml(c.name ?? '');
      const ver = c.version ? `@${escapeHtml(c.version)}` : '';
      return `<code>${name}${ver}</code>`;
    })
    .join(', ');
}

/** Format CVE IDs as a comma-separated list */
function formatCves(cves?: VulnerabilityOrViolationRow['cves']): string {
  if (!cves || cves.length === 0) return '—';
  return cves
    .map(c => (c.id ? escapeHtml(c.id) : ''))
    .filter(Boolean)
    .join(', ');
}

/** Format fixed versions as a comma-separated list */
function formatFixed(fixed?: string[]): string {
  if (!fixed || fixed.length === 0) return '—';
  return fixed.map(v => escapeHtml(v)).join(', ');
}

/** Format policies list */
function formatPolicies(policies?: string[]): string {
  if (!policies || policies.length === 0) return '—';
  return policies.map(p => escapeHtml(p)).join(', ');
}

// ---------------------------------------------------------------------------
// Scan status helpers
// ---------------------------------------------------------------------------

export function hasFailedScans(status?: ScanStatus): boolean {
  if (!status) return false;
  return (
    (status.scaScanStatusCode != null && status.scaScanStatusCode !== 0) ||
    (status.sastScanStatusCode != null && status.sastScanStatusCode !== 0) ||
    (status.iacScanStatusCode != null && status.iacScanStatusCode !== 0) ||
    (status.secretsScanStatusCode != null && status.secretsScanStatusCode !== 0) ||
    (status.ContextualAnalysisScanStatusCode != null &&
      status.ContextualAnalysisScanStatusCode !== 0)
  );
}

function statusLabel(code?: number): string {
  if (code == null) return '—';
  if (code === 0) return '✅ Success';
  return `❌ Error (code ${code})`;
}

function renderScanStatusTable(status?: ScanStatus): string {
  if (!status) return '';
  const rows: string[][] = [
    ['Software Composition Analysis (SCA)', statusLabel(status.scaScanStatusCode)],
    ['Contextual Analysis (CA)', statusLabel(status.ContextualAnalysisScanStatusCode)],
    ['Secrets', statusLabel(status.secretsScanStatusCode)],
    ['IaC', statusLabel(status.iacScanStatusCode)],
    ['SAST', statusLabel(status.sastScanStatusCode)],
  ].filter(row => row[1] !== '—'); // Only show scans that actually ran

  if (rows.length === 0) return '';
  return htmlTable(['Scan Type', 'Status'], rows);
}

// ---------------------------------------------------------------------------
// Section visibility
// ---------------------------------------------------------------------------

/**
 * Whether to show the plain vulnerabilities section (not violations).
 * Hidden when a policy scope is configured and vuln=false — in that mode
 * only violations from the policy are meaningful.
 */
export function shouldShowVulnerabilities(inputs: ActionInputs): boolean {
  if (!hasPolicyScope(inputs)) return true;
  return inputs.vuln;
}

// ---------------------------------------------------------------------------
// Overview table
// ---------------------------------------------------------------------------

function renderOverviewTable(results: SimpleJsonResults, inputs: ActionInputs): string {
  const allSeverities = SEVERITY_LABELS;

  interface ScanRow {
    label: string;
    rows: Array<{ severity?: string }>;
    show: boolean;
  }

  const showVulns = shouldShowVulnerabilities(inputs);

  const scanTypes: ScanRow[] = [
    {
      label: 'SCA Vulnerabilities',
      rows: results.vulnerabilities ?? [],
      show: showVulns,
    },
    {
      label: 'Security Violations',
      rows: results.securityViolations ?? [],
      show: true,
    },
    {
      label: 'Secrets',
      rows: [...(results.secrets ?? []), ...(results.secretsViolations ?? [])],
      show: true,
    },
    {
      label: 'IaC Issues',
      rows: [...(results.iac ?? []), ...(results.iacViolations ?? [])],
      show: true,
    },
    {
      label: 'SAST Issues',
      rows: [...(results.sast ?? []), ...(results.sastViolations ?? [])],
      show: true,
    },
    {
      label: 'License Violations',
      rows: results.licensesViolations ?? [],
      show: true,
    },
    {
      label: 'Operational Risk',
      rows: results.operationalRiskViolations ?? [],
      show: true,
    },
  ].filter(s => s.show && s.rows.length > 0);

  if (scanTypes.length === 0) return '';

  const headerCols = allSeverities.map(s => `${smallSeverityBadge(s)} ${s}`);
  const headers = ['Scan Type', 'Total', ...headerCols];

  const tableRows = scanTypes.map(scan => {
    const bySev = countBySeverity(scan.rows);
    const total = scan.rows.length;
    const sevCells = allSeverities.map(s => String(bySev[s] ?? 0));
    return [escapeHtml(scan.label), String(total), ...sevCells];
  });

  return htmlTable(headers, tableRows);
}

// ---------------------------------------------------------------------------
// Vulnerability / violation tables
// ---------------------------------------------------------------------------

function renderVulnRows(rows: VulnerabilityOrViolationRow[], includeViolationCols: boolean): string[][] {
  return sortFindings(rows).map(row => {
    const cells = [
      severityCell(row.severity, row.applicable),
      `<strong>${escapeHtml(row.impactedPackageName ?? '—')}</strong>`,
      `${escapeHtml(row.impactedPackageVersion ?? '')}`,
      escapeHtml(row.impactedPackageType ?? '—'),
      formatDirectDeps(row.components),
      formatCves(row.cves),
      formatFixed(row.fixedVersions),
      escapeHtml(row.applicable ?? '—'),
    ];
    if (includeViolationCols) {
      cells.push(
        escapeHtml(row.watch ?? '—'),
        formatPolicies(row.policies),
        row.fail_pull_request ? '✅' : '—',
        row.fail_build ? '✅' : '—',
      );
    }
    return cells;
  });
}

function vulnHeaders(includeViolationCols: boolean): string[] {
  const base = [
    'Severity',
    'Package',
    'Version',
    'Type',
    'Direct Dependency',
    'CVEs',
    'Fixed Versions',
    'Applicable',
  ];
  if (includeViolationCols) {
    return [...base, 'Watch', 'Policies', 'Fail PR', 'Fail Build'];
  }
  return base;
}

// ---------------------------------------------------------------------------
// Source code row tables (Secrets, IaC, SAST)
// ---------------------------------------------------------------------------

function renderSourceRows(rows: SourceCodeRow[], includeCwe: boolean, includeViolationCols: boolean): string[][] {
  return sortSourceRows(rows).map(row => {
    const finding = escapeHtml(truncate(row.finding ?? row.snippet ?? '—'));
    const cells = [
      severityCell(row.severity),
      escapeHtml(row.file ?? '—'),
      row.startLine != null ? String(row.startLine) : '—',
      escapeHtml(row.ruleId ?? row.scannerShortDescription ?? '—'),
    ];
    if (includeCwe) {
      cells.push(escapeHtml((row.cwe ?? []).join(', ') || '—'));
    }
    cells.push(`<code>${finding}</code>`);
    if (includeViolationCols) {
      cells.push(escapeHtml(row.watch ?? '—'), formatPolicies(row.policies));
    }
    return cells;
  });
}

function sourceHeaders(includeCwe: boolean, includeViolationCols: boolean): string[] {
  const base = ['Severity', 'File', 'Line', 'Rule'];
  if (includeCwe) base.push('CWE');
  base.push('Finding');
  if (includeViolationCols) {
    base.push('Watch', 'Policies');
  }
  return base;
}

// ---------------------------------------------------------------------------
// License tables
// ---------------------------------------------------------------------------

function renderLicenseViolationRows(rows: LicenseViolationRow[]): string[][] {
  return rows.map(row => [
    severityCell(row.severity),
    escapeHtml(row.impactedPackageName ?? '—'),
    escapeHtml(row.impactedPackageVersion ?? '—'),
    escapeHtml(row.licenseKey ?? '—'),
    escapeHtml(row.watch ?? '—'),
    formatPolicies(row.policies),
  ]);
}

function renderLicenseRows(rows: LicenseRow[]): string[][] {
  return rows.map(row => [
    escapeHtml(row.impactedPackageName ?? '—'),
    escapeHtml(row.impactedPackageVersion ?? '—'),
    escapeHtml(row.licenseKey ?? '—'),
    escapeHtml(row.licenseName ?? '—'),
  ]);
}

// ---------------------------------------------------------------------------
// Operational risk table
// ---------------------------------------------------------------------------

function renderOperationalRiskRows(rows: OperationalRiskViolationRow[]): string[][] {
  return rows.map(row => [
    severityCell(row.severity),
    escapeHtml(row.impactedPackageName ?? '—'),
    escapeHtml(row.impactedPackageVersion ?? '—'),
    escapeHtml(row.riskReason ?? '—'),
    row.isEndOfLife === 'true' ? '⚠️ Yes' : (row.isEndOfLife === 'false' ? 'No' : '—'),
    escapeHtml(row.latestVersion ?? '—'),
    escapeHtml(row.watch ?? '—'),
  ]);
}

// ---------------------------------------------------------------------------
// Errors table
// ---------------------------------------------------------------------------

function renderErrors(results: SimpleJsonResults): string {
  const errors = results.errors;
  if (!errors || errors.length === 0) return '';

  const rows = errors.map(e => [
    `<code>${escapeHtml(e.filePath ?? '—')}</code>`,
    escapeHtml(e.errorMessage ?? '—'),
  ]);

  return (
    `\n\n---\n\n` +
    `### ⚠️ Scan Errors (${errors.length})\n\n` +
    `> Some files or modules could not be scanned. Review the errors below.\n\n` +
    htmlTable(['File / Path', 'Error'], rows)
  );
}

// ---------------------------------------------------------------------------
// Main summary builder
// ---------------------------------------------------------------------------

export async function buildSummary(
  results: SimpleJsonResults,
  inputs: ActionInputs,
  counts: FindingCounts,
  exitCode: number,
): Promise<void> {
  const s = core.summary;
  const showVulns = shouldShowVulnerabilities(inputs);
  const failedScans = hasFailedScans(results.scansStatus);

  // ---- Header -----------------------------------------------------------
  s.addHeading('JFrog Security Audit Results', 1);

  // Metadata
  const metaParts: string[] = [];
  if (results.multiScanId) metaParts.push(`**Scan ID:** \`${results.multiScanId}\``);
  const runAt = new Date().toUTCString();
  metaParts.push(`**Scanned at:** ${runAt}`);
  if (metaParts.length > 0) {
    s.addRaw(`<p>${metaParts.join(' &nbsp;|&nbsp; ')}</p>\n\n`);
  }

  // ---- Scan Status (shown FIRST if any scan failed) --------------------
  if (failedScans) {
    s.addHeading('Scan Status', 2);
    s.addRaw(
      `> ⚠️ One or more scans did not complete successfully. Results may be incomplete.\n\n`,
    );
    s.addRaw(renderScanStatusTable(results.scansStatus));
    s.addRaw('\n\n---\n\n');
  }

  // ---- No findings banner ----------------------------------------------
  const totalFindings =
    counts.vulnerabilities +
    counts.violations +
    counts.secrets +
    counts.iac +
    counts.sast;

  if (totalFindings === 0 && (results.errors?.length ?? 0) === 0) {
    s.addRaw(
      `\n<div align="center">\n\n` +
        `## ✅ No security issues detected\n\n` +
        `Your source code passed the JFrog security audit with no findings.\n\n` +
        `</div>\n\n`,
    );
  }

  // ---- Overview table --------------------------------------------------
  const overviewTable = renderOverviewTable(results, inputs);
  if (overviewTable) {
    s.addHeading('Overview', 2);
    s.addRaw(overviewTable);
    s.addRaw('\n\n');
  }

  // ---- Findings sections -----------------------------------------------

  // === VULNERABILITIES (only shown when policy scope absent or vuln=true) ===
  if (showVulns) {
    const vulns = results.vulnerabilities ?? [];
    const secrets = results.secrets ?? [];
    const iacFindings = results.iac ?? [];
    const sastFindings = results.sast ?? [];

    if (vulns.length > 0 || secrets.length > 0 || iacFindings.length > 0 || sastFindings.length > 0) {
      s.addHeading('Vulnerabilities', 2);

      if (vulns.length > 0) {
        s.addRaw(
          details(
            `⚠️ SCA Vulnerabilities (${vulns.length})`,
            htmlTable(vulnHeaders(false), renderVulnRows(vulns, false)),
          ),
        );
        s.addRaw('\n\n');
      }

      if (secrets.length > 0) {
        s.addRaw(
          details(
            `🔒 Secrets (${secrets.length})`,
            htmlTable(sourceHeaders(false, false), renderSourceRows(secrets, false, false)),
          ),
        );
        s.addRaw('\n\n');
      }

      if (iacFindings.length > 0) {
        s.addRaw(
          details(
            `🏗️ IaC Issues (${iacFindings.length})`,
            htmlTable(sourceHeaders(false, false), renderSourceRows(iacFindings, false, false)),
          ),
        );
        s.addRaw('\n\n');
      }

      if (sastFindings.length > 0) {
        s.addRaw(
          details(
            `🔬 SAST Issues (${sastFindings.length})`,
            htmlTable(sourceHeaders(true, false), renderSourceRows(sastFindings, true, false)),
          ),
        );
        s.addRaw('\n\n');
      }
    }
  }

  // === VIOLATIONS (always shown when they exist) ===
  const secViolations = results.securityViolations ?? [];
  const secretViolations = results.secretsViolations ?? [];
  const iacViolations = results.iacViolations ?? [];
  const sastViolations = results.sastViolations ?? [];
  const licViolations = results.licensesViolations ?? [];
  const opRisk = results.operationalRiskViolations ?? [];

  const totalViolations =
    secViolations.length +
    secretViolations.length +
    iacViolations.length +
    sastViolations.length +
    licViolations.length +
    opRisk.length;

  if (totalViolations > 0) {
    s.addHeading('Policy Violations', 2);

    if (secViolations.length > 0) {
      s.addRaw(
        details(
          `🚨 Security Violations (${secViolations.length})`,
          htmlTable(vulnHeaders(true), renderVulnRows(secViolations, true)),
        ),
      );
      s.addRaw('\n\n');
    }

    if (secretViolations.length > 0) {
      s.addRaw(
        details(
          `🚨 Secrets Violations (${secretViolations.length})`,
          htmlTable(sourceHeaders(false, true), renderSourceRows(secretViolations, false, true)),
        ),
      );
      s.addRaw('\n\n');
    }

    if (iacViolations.length > 0) {
      s.addRaw(
        details(
          `🚨 IaC Violations (${iacViolations.length})`,
          htmlTable(sourceHeaders(false, true), renderSourceRows(iacViolations, false, true)),
        ),
      );
      s.addRaw('\n\n');
    }

    if (sastViolations.length > 0) {
      s.addRaw(
        details(
          `🚨 SAST Violations (${sastViolations.length})`,
          htmlTable(sourceHeaders(true, true), renderSourceRows(sastViolations, true, true)),
        ),
      );
      s.addRaw('\n\n');
    }

    if (licViolations.length > 0) {
      s.addRaw(
        details(
          `📜 License Violations (${licViolations.length})`,
          htmlTable(
            ['Severity', 'Package', 'Version', 'License', 'Watch', 'Policies'],
            renderLicenseViolationRows(licViolations),
          ),
        ),
      );
      s.addRaw('\n\n');
    }

    if (opRisk.length > 0) {
      s.addRaw(
        details(
          `⚙️ Operational Risk Violations (${opRisk.length})`,
          htmlTable(
            ['Severity', 'Package', 'Version', 'Risk Reason', 'EOL', 'Latest Version', 'Watch'],
            renderOperationalRiskRows(opRisk),
          ),
        ),
      );
      s.addRaw('\n\n');
    }
  }

  // === DISCOVERED LICENSES (informational, no severity) ===
  const discoveredLicenses = results.licenses ?? [];
  if (inputs.licenses && discoveredLicenses.length > 0) {
    s.addRaw(
      details(
        `📋 Discovered Licenses (${discoveredLicenses.length})`,
        htmlTable(
          ['Package', 'Version', 'License Key', 'License Name'],
          renderLicenseRows(discoveredLicenses),
        ),
      ),
    );
    s.addRaw('\n\n');
  }

  // === ERRORS (never collapsed) ===
  const errorsSection = renderErrors(results);
  if (errorsSection) {
    s.addRaw(errorsSection);
    s.addRaw('\n\n');
  }

  // ---- Scan Status at bottom (when all scans succeeded) ----------------
  if (!failedScans && results.scansStatus) {
    const statusTable = renderScanStatusTable(results.scansStatus);
    if (statusTable) {
      s.addRaw('\n\n---\n\n');
      s.addHeading('Scan Status', 2);
      s.addRaw(statusTable);
      s.addRaw('\n\n');
    }
  }

  // ---- Footer ----------------------------------------------------------
  s.addRaw(
    `\n\n---\n\n` +
      `<sub>Powered by <a href="https://github.com/jfrog/setup-jfrog-cli">JFrog CLI</a> ` +
      `&nbsp;|&nbsp; ` +
      `<a href="https://docs.jfrog.com/security/docs/scan-your-source-code">JFrog Security Docs</a></sub>\n`,
  );

  await s.write();
}
