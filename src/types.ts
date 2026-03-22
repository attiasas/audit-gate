// TypeScript interfaces mirroring the JFrog CLI simple-json output format.
// Source: github.com/jfrog/jfrog-cli-security/utils/formats/simplejsonapi.go
// IMPORTANT: Field names must match the JSON tags exactly.

export interface CveRow {
  id?: string;
  cvssV2?: string;
  cvssV2Vector?: string;
  cvssV3?: string;
  cvssV3Vector?: string;
  cwe?: string[];
  applicability?: Applicability;
}

export interface Applicability {
  status?: string;
  scannerDescription?: string;
  undeterminedReason?: string;
  evidence?: Evidence[];
}

export interface Evidence {
  file?: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
  reason?: string;
}

export interface ComponentRow {
  id?: string;
  name?: string;
  version?: string;
  location?: Location;
  evidences?: Evidence[];
}

export interface Location {
  file?: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
  externalReferences?: string[];
}

export interface SeverityDetails {
  severity?: string;
}

export interface ImpactedDependencyDetails extends SeverityDetails {
  impactedPackageName?: string;
  impactedPackageVersion?: string;
  impactedPackageType?: string;
  /** Direct components that introduce the impacted package (may be multiple) */
  components?: ComponentRow[];
}

export interface ViolationContext {
  watch?: string;
  issueId?: string;
  policies?: string[];
  /** json: fail_pull_request */
  fail_pull_request?: boolean;
  /** json: fail_build */
  fail_build?: boolean;
}

/** Used for SCA vulnerabilities and security violations */
export interface VulnerabilityOrViolationRow extends ImpactedDependencyDetails, ViolationContext {
  summary?: string;
  applicable?: string;
  fixedVersions?: string[];
  cves?: CveRow[];
  references?: string[];
  impactPaths?: ComponentRow[][];
  jfrogResearchInformation?: JfrogResearchInformation;
}

export interface JfrogResearchInformation extends SeverityDetails {
  summary?: string;
  details?: string;
  severityReasons?: JfrogResearchSeverityReason[];
  remediation?: string;
}

export interface JfrogResearchSeverityReason {
  name?: string;
  description?: string;
  isPositive?: boolean;
}

export interface LicenseRow extends ImpactedDependencyDetails {
  licenseKey?: string;
  licenseName?: string;
  impactPaths?: ComponentRow[][];
}

export interface LicenseViolationRow extends LicenseRow, ViolationContext {}

export interface OperationalRiskViolationRow extends ImpactedDependencyDetails, ViolationContext {
  riskReason?: string;
  isEndOfLife?: string;
  endOfLifeMessage?: string;
  cadence?: string;
  commits?: string;
  committers?: string;
  newerVersions?: string;
  latestVersion?: string;
}

export interface ScannerInfo {
  ruleId?: string;
  origin?: string;
  cwe?: string[];
  scannerShortDescription?: string;
  scannerDescription?: string;
}

export interface SourceCodeRow extends SeverityDetails, ViolationContext, ScannerInfo {
  file?: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
  finding?: string;
  fingerprint?: string;
  applicability?: Applicability;
  codeFlow?: Location[][];
}

export interface ScanStatus {
  scaScanStatusCode?: number;
  sastScanStatusCode?: number;
  iacScanStatusCode?: number;
  secretsScanStatusCode?: number;
  /** json: ContextualAnalysisScanStatusCode */
  ContextualAnalysisScanStatusCode?: number;
}

export interface SimpleJsonError {
  filePath?: string;
  errorMessage?: string;
}

export interface SimpleJsonResults {
  vulnerabilities?: VulnerabilityOrViolationRow[];
  securityViolations?: VulnerabilityOrViolationRow[];
  licensesViolations?: LicenseViolationRow[];
  licenses?: LicenseRow[];
  operationalRiskViolations?: OperationalRiskViolationRow[];
  /** json: "secrets" */
  secrets?: SourceCodeRow[];
  /** json: "iac" */
  iac?: SourceCodeRow[];
  /** json: "sast" */
  sast?: SourceCodeRow[];
  secretsViolations?: SourceCodeRow[];
  iacViolations?: SourceCodeRow[];
  sastViolations?: SourceCodeRow[];
  errors?: SimpleJsonError[];
  scansStatus?: ScanStatus;
  multiScanId?: string;
}

/** Typed representation of all action inputs */
export interface ActionInputs {
  workingDirs?: string;
  exclusions?: string;
  project?: string;
  watches?: string;
  repoPath?: string;
  vuln: boolean;
  threads: number;
  fail: boolean;
  failOnPrPolicy: boolean;
  failOnBuildPolicy: boolean;
  sca: boolean;
  secrets: boolean;
  sast: boolean;
  iac: boolean;
  staticSca: boolean;
  snippet: boolean;
  licenses: boolean;
  forceNoGit: boolean;
}

/** Whether any policy scope inputs are configured */
export function hasPolicyScope(inputs: ActionInputs): boolean {
  return !!(inputs.project || inputs.watches || inputs.repoPath);
}

/** Return value from runAudit() */
export interface AuditResult {
  exitCode: number;
  results: SimpleJsonResults;
  rawOutput: string;
}

/** Aggregated finding counts */
export interface FindingCounts {
  vulnerabilities: number;
  violations: number;
  secrets: number;
  iac: number;
  sast: number;
  licenseViolations: number;
  operationalRisk: number;
  critical: number;
  high: number;
}
