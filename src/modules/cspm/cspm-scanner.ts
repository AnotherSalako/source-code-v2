import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand, GetBucketPolicyStatusCommand, GetBucketAclCommand } from "@aws-sdk/client-s3";
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { logger } from "../../config/logger";

// Read-only, by construction: every AWS call below is a Describe/List/Get.
// Nothing in this file — or anywhere this module is used — ever calls a
// Create/Put/Delete/Modify AWS API. The IAM policy this feature expects a
// client to grant is exactly AmazonS3ReadOnlyAccess + AmazonEC2ReadOnlyAccess
// + IAMReadOnlyAccess, not broader — same least-privilege discipline as the
// KMS key policy and the agent's Linux sudoers grant elsewhere in this app.
//
// Bounded, same reasoning as MAX_CANDIDATES/MAX_RUNTIME_MS in
// discovery-runner.ts: a client's AWS account could have thousands of
// buckets or security groups. This checks the first MAX_RESOURCES_PER_CHECK
// of each and stops — a partial real scan beats an unbounded one that
// might never return.
const MAX_RESOURCES_PER_CHECK = 100;
const SENSITIVE_PORTS = new Set([22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5984]);

export interface CspmIssue {
  resourceType: "S3_BUCKET" | "SECURITY_GROUP" | "IAM_POLICY";
  resourceId: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
}

export interface CspmCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

function clientConfig(creds: CspmCredentials) {
  return { region: creds.region, credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey } };
}

/**
 * A bucket is flagged public if either its own Public Access Block doesn't
 * restrict everything, AND (its bucket policy is computed public by AWS's
 * own policy-status check, OR its ACL grants to the AllUsers/
 * AuthenticatedUsers well-known group URIs). Three separate signals
 * because any one alone can under- or over-report: a restrictive Public
 * Access Block overrides a permissive policy/ACL, so that's checked first
 * and short-circuits the rest when it's fully locked down.
 */
async function checkS3PublicBuckets(creds: CspmCredentials): Promise<CspmIssue[]> {
  const s3 = new S3Client(clientConfig(creds));
  const issues: CspmIssue[] = [];

  let buckets;
  try {
    buckets = (await s3.send(new ListBucketsCommand({}))).Buckets ?? [];
  } catch (err) {
    logger.warn({ err }, "CSPM: S3 ListBuckets failed — skipping S3 checks");
    return [];
  }

  for (const bucket of buckets.slice(0, MAX_RESOURCES_PER_CHECK)) {
    const name = bucket.Name;
    if (!name) continue;

    try {
      const block = await s3.send(new GetPublicAccessBlockCommand({ Bucket: name })).catch(() => null);
      const cfg = block?.PublicAccessBlockConfiguration;
      const fullyBlocked = cfg?.BlockPublicAcls && cfg?.IgnorePublicAcls && cfg?.BlockPublicPolicy && cfg?.RestrictPublicBuckets;
      if (fullyBlocked) continue; // Public Access Block overrides policy/ACL — genuinely not public regardless of what's below

      const policyStatus = await s3.send(new GetBucketPolicyStatusCommand({ Bucket: name })).catch(() => null);
      if (policyStatus?.PolicyStatus?.IsPublic) {
        issues.push({
          resourceType: "S3_BUCKET",
          resourceId: name,
          title: `S3 bucket "${name}" has a policy that makes it public`,
          severity: "CRITICAL",
          description: "AWS's own policy-status check reports this bucket's bucket policy grants public access, and no Public Access Block setting overrides it.",
        });
        continue; // one issue per bucket is enough — don't also report the ACL below for the same underlying exposure
      }

      const acl = await s3.send(new GetBucketAclCommand({ Bucket: name })).catch(() => null);
      const publicGrant = acl?.Grants?.find(
        (g) => g.Grantee?.URI === "http://acs.amazonaws.com/groups/global/AllUsers" || g.Grantee?.URI === "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
      );
      if (publicGrant) {
        issues.push({
          resourceType: "S3_BUCKET",
          resourceId: name,
          title: `S3 bucket "${name}" has a public ACL grant`,
          severity: "HIGH",
          description: `Bucket ACL grants ${publicGrant.Permission} to ${publicGrant.Grantee?.URI?.split("/").pop()}, and no Public Access Block setting overrides it.`,
        });
      }
    } catch (err) {
      logger.warn({ err, bucket: name }, "CSPM: S3 bucket check failed — skipping this bucket");
    }
  }

  return issues;
}

/** Any ingress rule open to 0.0.0.0/0 or ::/0 — severity bumped for known-sensitive ports (SSH, RDP, databases) or an all-ports rule. */
async function checkOpenSecurityGroups(creds: CspmCredentials): Promise<CspmIssue[]> {
  const ec2 = new EC2Client(clientConfig(creds));
  const issues: CspmIssue[] = [];

  let groups;
  try {
    groups = (await ec2.send(new DescribeSecurityGroupsCommand({}))).SecurityGroups ?? [];
  } catch (err) {
    logger.warn({ err }, "CSPM: EC2 DescribeSecurityGroups failed — skipping EC2 checks");
    return [];
  }

  for (const group of groups.slice(0, MAX_RESOURCES_PER_CHECK)) {
    const groupId = group.GroupId ?? "unknown";
    for (const perm of group.IpPermissions ?? []) {
      const openToWorld = (perm.IpRanges ?? []).some((r) => r.CidrIp === "0.0.0.0/0") || (perm.Ipv6Ranges ?? []).some((r) => r.CidrIpv6 === "::/0");
      if (!openToWorld) continue;

      const allPorts = perm.FromPort === undefined && perm.ToPort === undefined;
      const fromPort = perm.FromPort ?? 0;
      const toPort = perm.ToPort ?? 65535;
      const hitsSensitivePort = allPorts || Array.from(SENSITIVE_PORTS).some((p) => p >= fromPort && p <= toPort);

      issues.push({
        resourceType: "SECURITY_GROUP",
        resourceId: groupId,
        title: `Security group ${groupId} (${group.GroupName ?? "unnamed"}) allows ${allPorts ? "all ports" : `${fromPort}-${toPort}`} from the internet`,
        severity: allPorts ? "CRITICAL" : hitsSensitivePort ? "CRITICAL" : "HIGH",
        description: `Ingress rule permits ${perm.IpProtocol ?? "all protocols"} on ${allPorts ? "all ports" : `${fromPort}-${toPort}`} from 0.0.0.0/0 or ::/0.`,
      });
    }
  }

  return issues;
}

/** Flags customer-managed policies (never AWS-managed ones — those aren't something the client wrote or can edit) granting "*" action on "*" resource. */
async function checkOverlyBroadIamPolicies(creds: CspmCredentials): Promise<CspmIssue[]> {
  const iam = new IAMClient(clientConfig(creds));
  const issues: CspmIssue[] = [];

  let policies;
  try {
    policies = (await iam.send(new ListPoliciesCommand({ Scope: "Local", MaxItems: MAX_RESOURCES_PER_CHECK }))).Policies ?? [];
  } catch (err) {
    logger.warn({ err }, "CSPM: IAM ListPolicies failed — skipping IAM checks");
    return [];
  }

  for (const policy of policies) {
    if (!policy.Arn || !policy.PolicyId || !policy.DefaultVersionId) continue;
    try {
      const version = await iam.send(new GetPolicyVersionCommand({ PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId }));
      const rawDoc = version.PolicyVersion?.Document;
      if (!rawDoc) continue;
      const doc = JSON.parse(decodeURIComponent(rawDoc));
      const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];

      const hasFullAdmin = statements.some((s: any) => {
        if (s.Effect !== "Allow") return false;
        const actions = Array.isArray(s.Action) ? s.Action : [s.Action];
        const resources = Array.isArray(s.Resource) ? s.Resource : [s.Resource];
        return actions.includes("*") && resources.includes("*");
      });

      if (hasFullAdmin) {
        issues.push({
          resourceType: "IAM_POLICY",
          resourceId: policy.Arn,
          title: `IAM policy "${policy.PolicyName}" grants full admin (Action: *, Resource: *)`,
          severity: "CRITICAL",
          description: "This customer-managed policy has a statement allowing every action on every resource — equivalent to AdministratorAccess.",
        });
      }
    } catch (err) {
      logger.warn({ err, policy: policy.Arn }, "CSPM: IAM policy check failed — skipping this policy");
    }
  }

  return issues;
}

export async function runCspmScan(creds: CspmCredentials): Promise<CspmIssue[]> {
  const [s3Issues, sgIssues, iamIssues] = await Promise.all([
    checkS3PublicBuckets(creds),
    checkOpenSecurityGroups(creds),
    checkOverlyBroadIamPolicies(creds),
  ]);
  return [...s3Issues, ...sgIssues, ...iamIssues];
}

/** One real, cheap read-only call — used to confirm a submitted credential actually authenticates before it's ever stored. */
export async function verifyCredentials(creds: CspmCredentials): Promise<{ valid: boolean; error?: string }> {
  try {
    await new S3Client(clientConfig(creds)).send(new ListBucketsCommand({}));
    return { valid: true };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : String(err) };
  }
}
