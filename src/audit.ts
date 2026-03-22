import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import * as path from 'path';
import { ActionInputs, AuditResult, SimpleJsonResults } from './types';
import {
  assertMinCliVersion,
  buildAuditArgs,
  detectCliVersion,
  getCliCapabilities,
} from './cli-version';

const SETUP_JF_CLI_URL = 'https://github.com/jfrog/setup-jfrog-cli';

/** Check whether the jf CLI binary is available on PATH */
export async function isJfAvailable(): Promise<boolean> {
  try {
    const { exitCode } = await exec.getExecOutput('jf', ['--version'], {
      ignoreReturnCode: true,
      silent: true,
    });
    return exitCode === 0;
  } catch {
    return false;
  }
}

/** Check whether the current working directory is inside a git repository */
export async function isGitRepo(): Promise<boolean> {
  try {
    const { exitCode } = await exec.getExecOutput('git', ['rev-parse', '--git-dir'], {
      ignoreReturnCode: true,
      silent: true,
    });
    return exitCode === 0;
  } catch {
    return false;
  }
}

/**
 * Parse the JSON output from `jf audit --format simple-json`.
 *
 * The CLI may emit progress or warning lines to stdout before the JSON payload,
 * so we locate the first `{` and parse from there.
 */
export function parseJsonOutput(raw: string): SimpleJsonResults {
  const trimmed = raw.trim();
  const jsonStart = trimmed.indexOf('{');
  if (jsonStart === -1) {
    core.debug('No JSON object found in CLI output — treating as empty results');
    return {};
  }
  try {
    return JSON.parse(trimmed.slice(jsonStart)) as SimpleJsonResults;
  } catch (err) {
    core.warning(`Failed to parse CLI JSON output: ${err}`);
    core.debug(`Raw output:\n${raw}`);
    return {};
  }
}

/** Save raw audit output to the runner's temp directory for debugging */
function saveRawOutput(raw: string): void {
  try {
    const tmpDir = process.env.RUNNER_TEMP ?? '/tmp';
    const outPath = path.join(tmpDir, 'audit-gate-raw.json');
    fs.writeFileSync(outPath, raw, 'utf8');
    core.debug(`Raw audit output saved to ${outPath}`);
  } catch (err) {
    core.debug(`Could not save raw output: ${err}`);
  }
}

/**
 * Run the JFrog CLI audit command and return the parsed results.
 *
 * Steps:
 * 1. Verify `jf` is available
 * 2. Detect and validate CLI version
 * 3. Choose `jf git audit` vs `jf audit`
 * 4. Execute with `--format simple-json --fail=false`
 * 5. Parse stdout as JSON
 */
export async function runAudit(inputs: ActionInputs): Promise<AuditResult> {
  // 1. Ensure jf is installed
  const available = await isJfAvailable();
  if (!available) {
    core.setFailed(
      `JFrog CLI ('jf') is not installed or not found on PATH.\n` +
        `Add the setup-jfrog-cli action before this step: ${SETUP_JF_CLI_URL}`,
    );
    throw new Error('jf CLI not found');
  }

  // 2. Detect version and validate minimum
  const version = await detectCliVersion();
  assertMinCliVersion(version);

  // assertMinCliVersion throws if version is null or too old, so version is safe here
  const caps = getCliCapabilities(version!);

  // 3. Determine which audit subcommand to use
  const useGitAudit = !inputs.forceNoGit && (await isGitRepo());
  core.info(
    useGitAudit
      ? 'Using `jf git audit` (git repository detected)'
      : 'Using `jf audit` (no git context)',
  );

  // 4. Build and execute the command
  const args = buildAuditArgs(inputs, useGitAudit, caps);
  core.info(`Running: jf ${args.join(' ')}`);

  const { exitCode, stdout, stderr } = await exec.getExecOutput('jf', args, {
    ignoreReturnCode: true,
  });

  if (stderr) {
    core.debug(`CLI stderr:\n${stderr}`);
  }

  // Exit code 3 = fail-build rule was matched by Xray policy.
  // We always run with --fail=false so exit code 3 indicates the CLI evaluated policies
  // and found violations. We handle failure ourselves based on the parsed results.
  if (exitCode === 3) {
    core.info('JFrog CLI exit code 3: a fail-build policy rule was matched.');
  } else if (exitCode !== 0) {
    core.warning(`JFrog CLI exited with unexpected code ${exitCode}. Results may be incomplete.`);
  }

  // 5. Save raw output and parse
  saveRawOutput(stdout);
  const results = parseJsonOutput(stdout);

  return { exitCode, results, rawOutput: stdout };
}
