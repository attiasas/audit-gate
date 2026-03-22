/**
 * CLI version detection and capability mapping.
 *
 * This is the SINGLE EDIT POINT for CLI version-specific flag logic.
 * When a new JFrog CLI version adds, removes, or renames flags:
 *   1. Update MIN_CLI_VERSION if the requirement changed.
 *   2. Add a new entry to CLI_FEATURES.
 *   3. Add the flag usage to buildAuditArgs().
 *   No other files need to change.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { ActionInputs } from './types';

export interface CliVersion {
  major: number;
  minor: number;
  patch: number;
}

export interface CliCapabilities {
  /** --static-sca flag: supported since v2.90.0 (= MIN_CLI_VERSION) */
  supportsStaticSca: boolean;
  /** --snippet flag: supported since v2.94.0; requires --static-sca */
  supportsSnippet: boolean;
}

/** Minimum JFrog CLI version required to use this action */
export const MIN_CLI_VERSION: CliVersion = { major: 2, minor: 90, patch: 0 };

const CLI_FEATURES: Array<{
  capability: keyof CliCapabilities;
  minVersion: CliVersion;
  description: string;
}> = [
  {
    capability: 'supportsStaticSca',
    minVersion: { major: 2, minor: 90, patch: 0 },
    description: '--static-sca flag',
  },
  {
    capability: 'supportsSnippet',
    minVersion: { major: 2, minor: 94, patch: 0 },
    description: '--snippet flag (requires --static-sca)',
  },
];

/** Parse a version string like "2.91.0" or "jf version 2.91.0" into a CliVersion */
function parseVersion(raw: string): CliVersion | null {
  const match = raw.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
  };
}

/** Compare two CliVersion objects. Returns negative if a < b, 0 if equal, positive if a > b */
function compareVersions(a: CliVersion, b: CliVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

function formatVersion(v: CliVersion): string {
  return `${v.major}.${v.minor}.${v.patch}`;
}

/** Detect the installed JFrog CLI version by running `jf --version` */
export async function detectCliVersion(): Promise<CliVersion | null> {
  try {
    const { stdout } = await exec.getExecOutput('jf', ['--version'], {
      ignoreReturnCode: true,
      silent: true,
    });
    const version = parseVersion(stdout);
    if (version) {
      core.info(`Detected JFrog CLI version: ${formatVersion(version)}`);
    }
    return version;
  } catch {
    return null;
  }
}

/**
 * Assert that the detected CLI version meets the minimum requirement.
 * Throws an error (which sets the action as failed) if the version is too old.
 */
export function assertMinCliVersion(version: CliVersion | null): void {
  if (!version) {
    core.setFailed(
      `Could not detect JFrog CLI version. Minimum required: v${formatVersion(MIN_CLI_VERSION)}.\n` +
        `Please add the setup-jfrog-cli action: https://github.com/jfrog/setup-jfrog-cli`,
    );
    throw new Error('CLI version detection failed');
  }
  if (compareVersions(version, MIN_CLI_VERSION) < 0) {
    core.setFailed(
      `JFrog CLI v${formatVersion(version)} is below the minimum required v${formatVersion(MIN_CLI_VERSION)}.\n` +
        `Please upgrade: https://github.com/jfrog/setup-jfrog-cli`,
    );
    throw new Error(`CLI version too old: ${formatVersion(version)}`);
  }
}

/** Map a detected CLI version to its supported capabilities */
export function getCliCapabilities(version: CliVersion): CliCapabilities {
  const caps: CliCapabilities = {
    supportsStaticSca: false,
    supportsSnippet: false,
  };
  for (const feature of CLI_FEATURES) {
    if (compareVersions(version, feature.minVersion) >= 0) {
      caps[feature.capability] = true;
    }
  }
  return caps;
}

/**
 * Build the full argument list for the JFrog CLI audit command.
 *
 * This is the only function that needs to change when the CLI adds/removes flags.
 * Always includes: --format simple-json --fail=false
 */
export function buildAuditArgs(
  inputs: ActionInputs,
  useGitAudit: boolean,
  caps: CliCapabilities,
): string[] {
  const baseCmd = useGitAudit ? ['git', 'audit'] : ['audit'];
  const args: string[] = [...baseCmd, '--format', 'simple-json', '--fail=false'];

  // Optional scope / filtering
  if (inputs.workingDirs) args.push('--working-dirs', inputs.workingDirs);
  if (inputs.exclusions) args.push('--exclusions', inputs.exclusions);
  if (inputs.project) args.push('--project', inputs.project);
  if (inputs.watches) args.push('--watches', inputs.watches);
  if (inputs.repoPath) args.push('--repo-path', inputs.repoPath);
  if (inputs.threads > 0) args.push('--threads', String(inputs.threads));
  if (inputs.vuln) args.push('--vuln');
  if (inputs.licenses) args.push('--licenses');

  // Selective scan type flags — only add if at least one is explicitly enabled
  const anyExplicitScanType = inputs.sca || inputs.secrets || inputs.sast || inputs.iac;
  if (anyExplicitScanType) {
    if (inputs.sca) args.push('--sca');
    if (inputs.secrets) args.push('--secrets');
    if (inputs.sast) args.push('--sast');
    if (inputs.iac) args.push('--iac');
  }

  // Version-gated flags
  if (inputs.staticSca) {
    if (caps.supportsStaticSca) {
      args.push('--static-sca');
      if (inputs.snippet) {
        if (caps.supportsSnippet) {
          args.push('--snippet');
        } else {
          core.warning('--snippet flag requires JFrog CLI v2.94.0 or later; skipping.');
        }
      }
    } else {
      core.warning('--static-sca flag requires JFrog CLI v2.90.0 or later; skipping.');
    }
  } else if (inputs.snippet) {
    core.warning('--snippet flag has no effect without static-sca: true; skipping.');
  }

  return args;
}
