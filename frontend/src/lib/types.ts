export type Role = "SECURITY_ADMIN" | "TECHNICAL_CLIENT" | "EXEC_CLIENT";

export type EngagementStatus = "SCOPING" | "ACTIVE" | "REPORTING" | "RETEST" | "CLOSED";
export type AssetType = "WEB" | "MOBILE" | "SERVER" | "CLOUD" | "NETWORK" | "API";
export type Criticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type TestType = "VULN_SCAN" | "PENTEST" | "COMPLIANCE_REVIEW";
export type TestStatus = "PLANNED" | "IN_PROGRESS" | "COMPLETE";
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingStatus = "OPEN" | "REMEDIATING" | "RETESTED_PASS" | "RETESTED_FAIL" | "ACCEPTED_RISK";
export type ComplianceFramework = "NDPR" | "ISO27001" | "PCI_DSS" | "OTHER";
export type ComplianceStatus = "PENDING" | "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE";
export type ReportType = "EXECUTIVE" | "TECHNICAL" | "RETEST_ADDENDUM";
export type RetestResult = "FIXED" | "NOT_FIXED" | "PARTIALLY_FIXED";
export type RemediationEffort = "QUICK_WIN" | "SMALL" | "MEDIUM" | "LARGE";
export type RoadmapBucket = "quick_win" | "long_term" | "plan" | "uncategorized";
export type TrainingTopic = "PHISHING" | "PASSWORD_HYGIENE" | "DATA_HANDLING" | "APP_INFRA_MISTAKES" | "CUSTOM";
export type TrainingStatus = "SCHEDULED" | "COMPLETED" | "CANCELLED";
export type VerificationStatus = "UNVERIFIED" | "PENDING" | "VERIFIED";
export type VerificationMethod = "DNS_TXT" | "HTTP_FILE" | "MANUAL";
export type ScanJobStatus = "QUEUED" | "RUNNING" | "COMPLETE" | "FAILED";
export type MalwareStatus = "PENDING" | "CLEAN" | "FLAGGED" | "UNAVAILABLE";

export interface AuthUser {
  id: string;
  name: string;
  role: Role;
  orgId: string | null;
}

export interface Client {
  id: string;
  name: string;
  industry: string | null;
  createdAt: string;
  primaryContact?: string;
}

export type AuthorizationMethod = "MANUAL" | "ESIGNATURE";
export type AuthorizationRequestStatus = "SENT" | "SIGNED" | "DECLINED" | "VOIDED";

export interface Engagement {
  id: string;
  clientId: string;
  client?: { id: string; name: string };
  status: EngagementStatus;
  authorizedBy: string | null;
  authorizationSignedAt: string | null;
  authorizationMethod: AuthorizationMethod | null;
  authorizationRequestStatus: AuthorizationRequestStatus | null;
  authorizationEnvelopeId: string | null;
  startDate: string | null;
  endDate: string | null;
  createdAt: string;
  assumptions?: string;
  exclusions?: string;
}

export interface Asset {
  id: string;
  type: AssetType;
  name: string;
  criticality: Criticality;
  inScope: boolean;
  identifier: string;
  verificationStatus: VerificationStatus;
  verificationMethod: VerificationMethod | null;
  verifiedAt: string | null;
}

export interface ScanJob {
  id: string;
  assetId: string;
  testId: string | null;
  tool: string;
  status: ScanJobStatus;
  startedAt: string | null;
  completedAt: string | null;
  errorMessage: string | null;
  findingsCreated: number | null;
  findingsSkipped: number | null;
  createdAt: string;
  rawResult?: string;
}

export interface Test {
  id: string;
  engagementId: string;
  assetId: string;
  type: TestType;
  status: TestStatus;
  methodology: string | null;
  toolUsed: string | null;
}

export interface Finding {
  id: string;
  testId?: string;
  assetId?: string;
  title: string;
  severity: Severity;
  cvssScore: number | null;
  status: FindingStatus;
  remediationEffort?: RemediationEffort | null;
  discoveredAt?: string;
  description?: string;
  reproductionSteps?: string;
  remediationGuidance?: string;
}

export interface RoadmapItem {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  remediationEffort: RemediationEffort | null;
  assetId: string;
  discoveredAt: string;
  bucket: RoadmapBucket;
}

export interface TrainingSession {
  id: string;
  topic: TrainingTopic;
  customTopic: string | null;
  scheduledAt: string;
  status: TrainingStatus;
  attendeeCount: number | null;
  notes?: string;
}

export interface Evidence {
  id: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  uploadedAt: string;
  malwareStatus: MalwareStatus;
  malwareDetections: number | null;
}

export interface ComplianceCheck {
  id: string;
  framework: ComplianceFramework;
  controlId: string;
  controlName: string;
  status: ComplianceStatus;
}

export interface ComplianceSummary {
  totalControls: number;
  byFramework: Record<string, Record<ComplianceStatus, number>>;
}

export interface Report {
  id: string;
  type: ReportType;
  version: number;
  generatedAt: string;
}

export interface Retest {
  id: string;
  findingId: string;
  retestedAt: string;
  result: RetestResult;
}

export interface FindingsHistory {
  totalFindings: number;
  bySeverity: Partial<Record<Severity, number>>;
  byStatus: Partial<Record<FindingStatus, number>>;
  recurring: { title: string; assetId: string; occurrences: number }[];
  byEngagement: {
    engagementId: string;
    engagementCreatedAt: string;
    status: EngagementStatus;
    counts: Partial<Record<Severity, number>>;
    total: number;
  }[];
}

export interface SecurityStatus {
  access: {
    signupRestricted: boolean;
    teamSize: number;
    roleBreakdown: Record<Role, number>;
  };
  encryption: {
    kmsProvider: "local" | "aws";
    cmkVersion: number;
    rotationScheduled: boolean;
  };
  scanningSafety: {
    nonIntrusiveOnly: boolean;
    allowInternalTargets: boolean;
    scheduledScanningConfigured: boolean;
  };
  detectionResponse: {
    malwareDetectionConfigured: boolean;
    activeResponseProvider: "noop" | "crowdstrike";
    esignatureProvider: "noop" | "documenso";
    slackConfigured: boolean;
    emailConfigured: boolean;
  };
  audit: {
    totalEvents: number;
    deniedLast30Days: number;
  };
}

export interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: Role;
  orgId: string | null;
  lastLoginAt: string | null;
  createdAt: string;
}

export interface AuditLogEntry {
  id: string;
  userId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  result: "SUCCESS" | "DENIED";
  timestamp: string;
}
