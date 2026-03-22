import * as core from '@actions/core';
import { runAudit } from './audit';
import { buildSummary } from './summary';
import {
  ActionInputs,
  FindingCounts,
  SimpleJsonResults,
} from './types';

/** Read and validate all action inputs */
function readInputs(): ActionInputs {
  return {
    workingDirs: core.getInput('working-dirs') || undefined,
    exclusions: core.getInput('exclusions') || undefined,
    project: core.getInput('project') || undefined,
    watches: core.getInput('watches') || undefined,
    repoPath: core.getInput('repo-path') || undefined,
    vuln: core.getBooleanInput('vuln'),
    threads: parseInt(core.getInput('threads') || '5', 10),
    fail: core.getBooleanInput('fail'),
    failOnPrPolicy: core.getBooleanInput('fail-on-pr-policy'),
    failOnBuildPolicy: core.getBooleanInput('fail-on-build-policy'),
    sca: core.getBooleanInput('sca'),
    secrets: core.getBooleanInput('secrets'),
    sast: core.getBooleanInput('sast'),
    iac: core.getBooleanInput('iac'),
    staticSca: core.getBooleanInput('static-sca'),
    snippet: core.getBooleanInput('snippet'),
    licenses: core.getBooleanInput('licenses'),
    forceNoGit: core.getBooleanInput('force-no-git'),
  };
}

/** Aggregate all finding counts from parsed results */
function computeCounts(results: SimpleJsonResults): FindingCounts {
  const allRows: Array<{ severity?: string }> = [
    ...(results.vulnerabilities ?? []),
    ...(results.securityViolations ?? []),
    ...(results.secrets ?? []),
    ...(results.iac ?? []),
    ...(results.sast ?? []),
    ...(results.secretsViolations ?? []),
    ...(results.iacViolations ?? []),
    ...(results.sastViolations ?? []),
    ...(results.licensesViolations ?? []),
    ...(results.operationalRiskViolations ?? []),
  ];

  const criticalCount = allRows.filter(
    r => (r.severity ?? '').toLowerCase() === 'critical',
  ).length;
  const highCount = allRows.filter(r => (r.severity ?? '').toLowerCase() === 'high').length;

  return {
    vulnerabilities: results.vulnerabilities?.length ?? 0,
    violations:
      (results.securityViolations?.length ?? 0) +
      (results.licensesViolations?.length ?? 0) +
      (results.operationalRiskViolations?.length ?? 0),
    secrets:
      (results.secrets?.length ?? 0) + (results.secretsViolations?.length ?? 0),
    iac: (results.iac?.length ?? 0) + (results.iacViolations?.length ?? 0),
    sast: (results.sast?.length ?? 0) + (results.sastViolations?.length ?? 0),
    licenseViolations: results.licensesViolations?.length ?? 0,
    operationalRisk: results.operationalRiskViolations?.length ?? 0,
    critical: criticalCount,
    high: highCount,
  };
}

/** All violation row types that carry fail_pull_request / fail_build flags */
function allViolationRows(results: SimpleJsonResults): Array<{ fail_pull_request?: boolean; fail_build?: boolean }> {
  return [
    ...(results.securityViolations ?? []),
    ...(results.licensesViolations ?? []),
    ...(results.operationalRiskViolations ?? []),
    ...(results.secretsViolations ?? []),
    ...(results.iacViolations ?? []),
    ...(results.sastViolations ?? []),
  ];
}

/** Returns true if any violation has fail_pull_request: true */
function hasPrPolicyViolation(results: SimpleJsonResults): boolean {
  return allViolationRows(results).some(r => r.fail_pull_request === true);
}

/** Returns true if any violation has fail_build: true */
function hasBuildPolicyViolation(results: SimpleJsonResults): boolean {
  return allViolationRows(results).some(r => r.fail_build === true);
}

function buildFailMessage(
  counts: FindingCounts,
  prPolicy: boolean,
  buildPolicy: boolean,
): string {
  const parts: string[] = [];
  if (counts.vulnerabilities > 0) parts.push(`${counts.vulnerabilities} SCA vulnerabilities`);
  if (counts.violations > 0) parts.push(`${counts.violations} violations`);
  if (counts.secrets > 0) parts.push(`${counts.secrets} secrets`);
  if (counts.iac > 0) parts.push(`${counts.iac} IaC issues`);
  if (counts.sast > 0) parts.push(`${counts.sast} SAST issues`);
  if (prPolicy) parts.push('PR policy violation triggered');
  if (buildPolicy) parts.push('build policy violation triggered');
  return `Audit gate failed: ${parts.join(', ')}.`;
}

async function run(): Promise<void> {
  const inputs = readInputs();

  // Validate threads input
  if (isNaN(inputs.threads) || inputs.threads <= 0) {
    inputs.threads = 5;
  }

  // Run the audit
  const auditResult = await runAudit(inputs);
  const counts = computeCounts(auditResult.results);

  // Policy violation flags (independent of fail input)
  const prPolicyViolation = hasPrPolicyViolation(auditResult.results);
  const buildPolicyViolation = hasBuildPolicyViolation(auditResult.results);

  // Set all outputs
  core.setOutput('vulnerabilities-count', String(counts.vulnerabilities));
  core.setOutput('violations-count', String(counts.violations));
  core.setOutput('secrets-count', String(counts.secrets));
  core.setOutput('iac-count', String(counts.iac));
  core.setOutput('sast-count', String(counts.sast));
  core.setOutput('license-violations-count', String(counts.licenseViolations));
  core.setOutput('operational-risk-count', String(counts.operationalRisk));
  core.setOutput('critical-count', String(counts.critical));
  core.setOutput('high-count', String(counts.high));
  core.setOutput('scan-id', auditResult.results.multiScanId ?? '');
  core.setOutput('has-errors', String((auditResult.results.errors?.length ?? 0) > 0));
  core.setOutput('pr-policy-fail', String(prPolicyViolation));
  core.setOutput('build-policy-fail', String(buildPolicyViolation));

  // Build and write the job summary
  await buildSummary(auditResult.results, inputs, counts, auditResult.exitCode);

  // Determine pass/fail — three independent conditions OR'd together
  const totalFindings =
    counts.vulnerabilities +
    counts.violations +
    counts.secrets +
    counts.iac +
    counts.sast;

  const shouldFail =
    (inputs.fail && totalFindings > 0) ||
    (inputs.failOnPrPolicy && prPolicyViolation) ||
    (inputs.failOnBuildPolicy && buildPolicyViolation);

  core.setOutput('result', shouldFail ? 'fail' : 'pass');

  if (shouldFail) {
    core.setFailed(
      buildFailMessage(
        counts,
        inputs.failOnPrPolicy && prPolicyViolation,
        inputs.failOnBuildPolicy && buildPolicyViolation,
      ),
    );
  } else {
    core.info('✅ Audit gate passed.');
  }
}

run().catch(core.setFailed);
