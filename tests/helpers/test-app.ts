import { vi } from "vitest";
import crypto from "crypto";
import { LocalKmsProvider } from "../../src/crypto/kms";
import type { ObjectStorage } from "../../src/crypto/storage";

// Route-level integration harness: mocks Clerk, Prisma, object storage, and
// every third-party-backed module (esignature, threat response, scan runner,
// scan import, key rotation) to drive the real Express app — real routing,
// real Zod validation, real requireAuth/requireRole/assertOwnOrg, real
// envelope encryption (LocalKmsProvider is pure crypto, no network, so it
// runs for real rather than being faked) — through supertest, with no live
// Clerk instance, database, or external API. Auth is driven by an
// `x-test-user` header carrying the caller's email — see authHeader() below.

vi.mock("@clerk/express", () => ({
  clerkMiddleware: () => (_req: unknown, _res: unknown, next: () => void) => next(),
  getAuth: (req: { headers: Record<string, string | undefined> }) => ({ userId: req.headers["x-test-user"] ?? null }),
  clerkClient: {
    users: {
      getUser: async (userId: string) => ({
        primaryEmailAddress: { emailAddress: userId },
        emailAddresses: [{ emailAddress: userId }],
      }),
    },
    invitations: { createInvitation: vi.fn().mockResolvedValue({ id: "inv_test" }) },
    // security.routes.ts reads restriction state via an empty updateRestrictions
    // call (see that file's comment on why) — fixed to "restricted" in tests.
    instance: { updateRestrictions: vi.fn().mockResolvedValue({ allowlist: true }) },
  },
}));

// Third-party-backed modules unrelated to the RBAC/validation/IDOR behavior
// these tests exist to cover — mocked out entirely so route tests never make
// a real network call and aren't coupled to those modules' own internals
// (each has its own dedicated place to be tested, if/when it is).
vi.mock("../../src/esignature", () => ({
  esignature: {
    sendForSignature: vi.fn().mockResolvedValue({ envelopeId: "env_test", signingUrl: "https://example.com/sign" }),
    checkStatus: vi.fn().mockResolvedValue({ status: "SENT" }),
    getSignedDocument: vi.fn().mockResolvedValue(null),
  },
}));
vi.mock("../../src/threat-response", () => ({
  threatResponse: { containHost: vi.fn().mockResolvedValue({ success: true, message: "test containment" }) },
}));
vi.mock("../../src/modules/scanning/scan-runner", () => ({
  startScan: vi.fn().mockResolvedValue({ scanJobId: "scanjob_test", testId: "test_test" }),
  isPrivateAddress: vi.fn().mockReturnValue(false),
}));
vi.mock("../../src/modules/discovery/discovery-runner", () => ({
  startDiscovery: vi.fn().mockResolvedValue({ discoveryJobId: "discoveryjob_test" }),
}));
vi.mock("../../src/modules/findings/import.service", () => ({
  importScanItems: vi.fn().mockResolvedValue({ createdIds: [], skipped: [] }),
}));
vi.mock("../../src/crypto/rotation", () => ({
  rotateAllFields: vi.fn().mockResolvedValue([]),
}));
vi.mock("../../src/integrations/malware-check", () => ({
  checkEvidenceMalware: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../../src/notifications", () => ({
  notifyIfSevere: vi.fn().mockResolvedValue(undefined),
  notifySweepHeartbeat: vi.fn().mockResolvedValue(undefined),
}));
// Default mirrors NoopAiTriageProvider — no draft, same as AI_TRIAGE_PROVIDER
// unset. Individual tests override via vi.mocked(aiTriage.draftTriage) when
// exercising the drafted path.
vi.mock("../../src/ai", () => ({
  aiTriage: { draftTriage: vi.fn().mockResolvedValue(null) },
}));
vi.mock("../../src/modules/findings/triage.service", () => ({
  triageFinding: vi.fn().mockResolvedValue(undefined),
}));

// Real LocalKmsProvider (pure AES-256-GCM, no network) with a fixed test CMK
// — envelope encryption in tests is the real thing, not faked, so a bug in
// how a route calls encryptField/decryptField would actually surface.
const testKms = new LocalKmsProvider(crypto.randomBytes(32).toString("base64"), "test-cmk", 1);

// In-memory stand-in for object storage — same interface as
// LocalObjectStorage, just backed by a Map instead of the filesystem.
const testObjectStorage: ObjectStorage = (() => {
  const store = new Map<string, Buffer>();
  return {
    put: async (key, data) => void store.set(key, data),
    get: async (key) => {
      const data = store.get(key);
      if (!data) throw new Error(`No object at key ${key}`);
      return data;
    },
    exists: async (key) => store.has(key),
    delete: async (key) => void store.delete(key),
  };
})();

vi.mock("../../src/crypto", async () => {
  const envelope = await vi.importActual("../../src/crypto/envelope");
  return { ...envelope, kms: testKms, objectStorage: testObjectStorage };
});

export interface FakeUserRow {
  id: string;
  email: string;
  name: string;
  role: "SECURITY_ADMIN" | "TECHNICAL_CLIENT" | "EXEC_CLIENT";
  orgId: string | null;
  createdAt: Date;
  lastLoginAt: Date | null;
}

export interface FakeClientRow {
  id: string;
  name: string;
  industry: string | null;
  primaryContactEnc: unknown;
  billingInfoEnc: unknown;
  createdAt: Date;
  kmsKeyId: string | null;
}

export interface FakeEngagementRow {
  id: string;
  clientId: string;
  status: string;
  assumptionsEnc: unknown;
  exclusionsEnc: unknown;
  authorizedBy: string | null;
  authorizationSignedAt: Date | null;
  authorizationDocRef: string | null;
  authorizationDocIv: string | null;
  authorizationDocAuthTag: string | null;
  authorizationDocEncryptedDataKey: string | null;
  authorizationDocKmsKeyId: string | null;
  authorizationDocKeyVersion: number | null;
  authorizationMethod: string | null;
  authorizationEnvelopeId: string | null;
  authorizationRequestStatus: string | null;
  createdAt: Date;
}

export interface FakeAssetRow {
  id: string;
  engagementId: string;
  type: string;
  name: string;
  identifierEnc: unknown;
  owner: string | null;
  criticality: string;
  inScope: boolean;
  notesEnc: unknown;
  verificationStatus: string;
  verificationMethod: string | null;
  verificationToken: string | null;
  verifiedAt: Date | null;
  verifiedBy: string | null;
  createdAt: Date;
}

export interface FakeTestRow {
  id: string;
  engagementId: string;
  assetId: string;
  type: string;
  methodology: string | null;
  toolUsed: string | null;
  testerId: string;
  status: string;
  completedAt: Date | null;
}

export interface FakeFindingRow {
  id: string;
  testId: string;
  assetId: string;
  title: string;
  severity: string;
  cvssScore: number | null;
  descriptionEnc: unknown;
  reproductionStepsEnc: unknown;
  remediationGuidanceEnc: unknown;
  status: string;
  remediationEffort: string | null;
  discoveredAt: Date;
  aiRemediationDraftEnc: unknown;
  aiFalsePositiveLikelihood: string | null;
  aiTriageRationaleEnc: unknown;
  aiTriagedAt: Date | null;
}

export interface FakeEvidenceRow {
  id: string;
  findingId: string;
  originalFilename: string;
  mimeType: string;
  storageKey: string;
  iv: string;
  authTag: string;
  encryptedDataKey: string;
  kmsKeyId: string;
  keyVersion: number;
  sizeBytes: number;
  uploadedBy: string;
  sha256: string;
  uploadedAt: Date;
  malwareStatus: string;
  malwareDetections: number | null;
}

export interface FakeComplianceCheckRow {
  id: string;
  engagementId: string;
  framework: string;
  controlId: string;
  controlName: string;
  status: string;
  notesEnc: unknown;
  createdAt: Date;
}

export interface FakeReportRow {
  id: string;
  engagementId: string;
  type: string;
  version: number;
  storageKey: string;
  iv: string;
  authTag: string;
  encryptedDataKey: string;
  kmsKeyId: string;
  keyVersion: number;
  generatedBy: string;
  generatedAt: Date;
}

export interface FakeRetestRow {
  id: string;
  findingId: string;
  retestedBy: string;
  result: string;
  notesEnc: unknown;
  retestedAt: Date;
}

export interface FakeTrainingSessionRow {
  id: string;
  engagementId: string;
  topic: string;
  customTopic: string | null;
  scheduledAt: Date;
  status: string;
  attendeeCount: number;
  notesEnc: unknown;
}

export interface FakeScanJobRow {
  id: string;
  engagementId: string;
  assetId: string;
  testId: string;
  tool: string;
  status: string;
  startedAt: Date | null;
  completedAt: Date | null;
  errorMessage: string | null;
  findingsCreated: number;
  findingsSkipped: number;
  createdAt: Date;
  rawResultEnc: unknown;
}

export interface FakeDiscoveryJobRow {
  id: string;
  engagementId: string;
  assetId: string;
  tool: string;
  status: string;
  startedAt: Date | null;
  completedAt: Date | null;
  errorMessage: string | null;
  discoveredCount: number | null;
  createdAt: Date;
}

export interface FakeDiscoveredAssetRow {
  id: string;
  engagementId: string;
  parentAssetId: string;
  discoveryJobId: string;
  valueEnc: unknown;
  source: string;
  openPorts: number[];
  status: string;
  promotedAssetId: string | null;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  createdAt: Date;
}

export interface FakeKeyRefRow {
  id: string;
  purpose: string;
  kmsKeyId: string;
  keyVersion: number;
  resourceType: string;
  resourceId: string;
  status: string;
  createdAt: Date;
  retiredAt: Date | null;
}

export interface FakeAuditLogRow {
  id: string;
  userId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  engagementId: string | null;
  result: string;
  timestamp: Date;
}

const usersByEmail = new Map<string, FakeUserRow>();
const clientsById = new Map<string, FakeClientRow>();
const engagementsById = new Map<string, FakeEngagementRow>();
const assetsById = new Map<string, FakeAssetRow>();
const testsById = new Map<string, FakeTestRow>();
const findingsById = new Map<string, FakeFindingRow>();
const evidenceById = new Map<string, FakeEvidenceRow>();
const complianceChecksById = new Map<string, FakeComplianceCheckRow>();
const reportsById = new Map<string, FakeReportRow>();
const retestsById = new Map<string, FakeRetestRow>();
const trainingSessionsById = new Map<string, FakeTrainingSessionRow>();
const scanJobsById = new Map<string, FakeScanJobRow>();
const discoveryJobsById = new Map<string, FakeDiscoveryJobRow>();
const discoveredAssetsById = new Map<string, FakeDiscoveredAssetRow>();
const keyRefsById = new Map<string, FakeKeyRefRow>();
const auditLogs: FakeAuditLogRow[] = [];

// Real UUIDs, not human-readable "prefix_N" strings — several Zod schemas
// validate foreign-key fields with .uuid() (findings' assetId, engagements'
// clientId, etc.), so an ID a route hands back to a test that then gets
// echoed into a later request body must actually look like what Prisma's
// @default(uuid()) produces, or that later request 400s on validation.
const nextId = (_prefix: string) => crypto.randomUUID();

// Matches a fake row's field against either a bare Prisma equality condition
// or a `{ in: [...] }` filter — the two shapes the client-deletion service
// (and a growing number of other routes) actually send. `undefined` always
// matches, same as Prisma treating an absent where-clause key as "no filter."
function matchWhereField(value: unknown, cond: unknown): boolean {
  if (cond === undefined) return true;
  if (cond && typeof cond === "object" && "in" in (cond as any)) return (cond as { in: unknown[] }).in.includes(value);
  return value === cond;
}

function findingWithEngagement(findingId: string) {
  const finding = findingsById.get(findingId);
  if (!finding) return null;
  const test = testsById.get(finding.testId);
  const engagement = test ? engagementsById.get(test.engagementId) : undefined;
  return { finding, test, engagement };
}

const prismaMock = {
    user: {
      findUnique: vi.fn(async ({ where }: any) => {
        if (where.email) return usersByEmail.get(where.email) ?? null;
        if (where.id) return [...usersByEmail.values()].find((u) => u.id === where.id) ?? null;
        return null;
      }),
      findUniqueOrThrow: vi.fn(async ({ where }: any) => {
        const row = [...usersByEmail.values()].find((u) => u.id === where.id);
        if (!row) throw new Error("not found");
        return row;
      }),
      findMany: vi.fn(async () => [...usersByEmail.values()]),
      count: vi.fn(async (args: any = {}) => {
        const { where } = args;
        const all = [...usersByEmail.values()];
        if (!where) return all.length;
        return all.filter((u) => (where.role ? u.role === where.role : true)).length;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeUserRow = { id: nextId("user"), createdAt: new Date(), lastLoginAt: null, ...data };
        usersByEmail.set(row.email, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = [...usersByEmail.values()].find((u) => u.id === where.id)!;
        Object.assign(row, data);
        return row;
      }),
      delete: vi.fn(async ({ where }: any) => {
        const row = [...usersByEmail.values()].find((u) => u.id === where.id)!;
        usersByEmail.delete(row.email);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...usersByEmail.values()].filter((u) => matchWhereField(u.orgId, where?.orgId));
        for (const u of rows) usersByEmail.delete(u.email);
        return { count: rows.length };
      }),
    },
    client: {
      findUnique: vi.fn(async ({ where }: any) => clientsById.get(where.id) ?? null),
      findUniqueOrThrow: vi.fn(async ({ where }: any) => {
        const row = clientsById.get(where.id);
        if (!row) throw new Error("not found");
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => {
        const all = [...clientsById.values()];
        return where ? all.filter((c) => c.id === where.id) : all;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeClientRow = { id: nextId("client"), industry: null, primaryContactEnc: null, billingInfoEnc: null, createdAt: new Date(), kmsKeyId: null, ...data };
        clientsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = clientsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      delete: vi.fn(async ({ where }: any) => {
        const row = clientsById.get(where.id)!;
        clientsById.delete(where.id);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const ids = [...clientsById.keys()].filter((id) => matchWhereField(id, where?.id));
        for (const id of ids) clientsById.delete(id);
        return { count: ids.length };
      }),
    },
    engagement: {
      findUnique: vi.fn(async ({ where, select }: any) => {
        const row = engagementsById.get(where.id);
        if (!row) return null;
        if (select?.clientId && Object.keys(select).length === 1) return { clientId: row.clientId };
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => {
        let all = [...engagementsById.values()];
        if (where?.clientId) all = all.filter((e) => e.clientId === where.clientId);
        return all.map((e) => ({ ...e, client: clientsById.get(e.clientId) }));
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeEngagementRow = {
          id: nextId("engagement"),
          status: "SCOPING",
          assumptionsEnc: null,
          exclusionsEnc: null,
          authorizedBy: null,
          authorizationSignedAt: null,
          authorizationDocRef: null,
          authorizationDocIv: null,
          authorizationDocAuthTag: null,
          authorizationDocEncryptedDataKey: null,
          authorizationDocKmsKeyId: null,
          authorizationDocKeyVersion: null,
          authorizationMethod: null,
          authorizationEnvelopeId: null,
          authorizationRequestStatus: null,
          createdAt: new Date(),
          ...data,
        };
        engagementsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = engagementsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...engagementsById.values()];
        if (where?.id) rows = rows.filter((e) => matchWhereField(e.id, where.id));
        if (where?.clientId) rows = rows.filter((e) => matchWhereField(e.clientId, where.clientId));
        for (const e of rows) engagementsById.delete(e.id);
        return { count: rows.length };
      }),
    },
    asset: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = assetsById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: engagementsById.get(row.engagementId) };
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => [...assetsById.values()].filter((a) => matchWhereField(a.engagementId, where?.engagementId))),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeAssetRow = {
          id: nextId("asset"),
          owner: null,
          criticality: "MEDIUM",
          inScope: true,
          notesEnc: null,
          verificationStatus: "UNVERIFIED",
          verificationMethod: null,
          verificationToken: null,
          verifiedAt: null,
          verifiedBy: null,
          createdAt: new Date(),
          ...data,
        };
        assetsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = assetsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...assetsById.values()];
        if (where?.id) rows = rows.filter((a) => matchWhereField(a.id, where.id));
        if (where?.engagementId) rows = rows.filter((a) => matchWhereField(a.engagementId, where.engagementId));
        for (const a of rows) assetsById.delete(a.id);
        return { count: rows.length };
      }),
    },
    test: {
      findMany: vi.fn(async ({ where }: any) => [...testsById.values()].filter((t) => matchWhereField(t.engagementId, where?.engagementId))),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeTestRow = { id: nextId("test"), methodology: null, toolUsed: null, completedAt: null, ...data };
        testsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = testsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...testsById.values()];
        if (where?.id) rows = rows.filter((t) => matchWhereField(t.id, where.id));
        if (where?.engagementId) rows = rows.filter((t) => matchWhereField(t.engagementId, where.engagementId));
        for (const t of rows) testsById.delete(t.id);
        return { count: rows.length };
      }),
    },
    finding: {
      findUnique: vi.fn(async ({ where, include, select }: any) => {
        const ctx = findingWithEngagement(where.id);
        if (!ctx) return null;
        const { finding, test, engagement } = ctx;
        if (select) {
          const out: any = {};
          for (const key of Object.keys(select)) out[key] = (finding as any)[key];
          return out;
        }
        if (include?.test || include?.asset) {
          const result: any = { ...finding };
          if (include.test) result.test = { ...test, engagement: { clientId: engagement?.clientId } };
          if (include.asset) result.asset = assetsById.get(finding.assetId);
          return result;
        }
        return finding;
      }),
      findMany: vi.fn(async ({ where }: any) => {
        let all = [...findingsById.values()];
        const testEngagementId = where?.test?.engagementId;
        const testId = where?.test?.id;
        const testIdField = where?.testId;
        const statusIn = where?.status?.in as string[] | undefined;
        if (testEngagementId) {
          all = all.filter((f) => {
            const test = testsById.get(f.testId);
            return test?.engagementId === testEngagementId;
          });
        }
        if (testId) all = all.filter((f) => f.testId === testId);
        if (testIdField) all = all.filter((f) => matchWhereField(f.testId, testIdField));
        if (statusIn) all = all.filter((f) => statusIn.includes(f.status));
        return all.map((f) => ({ ...f, test: { engagementId: testsById.get(f.testId)?.engagementId } }));
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeFindingRow = {
          id: nextId("finding"),
          cvssScore: null,
          reproductionStepsEnc: null,
          remediationGuidanceEnc: null,
          status: "OPEN",
          remediationEffort: null,
          discoveredAt: new Date(),
          aiRemediationDraftEnc: null,
          aiFalsePositiveLikelihood: null,
          aiTriageRationaleEnc: null,
          aiTriagedAt: null,
          ...data,
        };
        findingsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = findingsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...findingsById.values()];
        if (where?.id) rows = rows.filter((f) => matchWhereField(f.id, where.id));
        if (where?.testId) rows = rows.filter((f) => matchWhereField(f.testId, where.testId));
        for (const f of rows) findingsById.delete(f.id);
        return { count: rows.length };
      }),
    },
    evidence: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = evidenceById.get(where.id);
        if (!row) return null;
        if (include?.finding) {
          const ctx = findingWithEngagement(row.findingId);
          return { ...row, finding: { ...ctx?.finding, test: { ...ctx?.test, engagement: { clientId: ctx?.engagement?.clientId } } } };
        }
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => {
        let all = [...evidenceById.values()];
        if (where?.findingId) all = all.filter((e) => matchWhereField(e.findingId, where.findingId));
        const nestedEngagementId = where?.finding?.test?.engagementId;
        if (nestedEngagementId) {
          all = all.filter((e) => {
            const finding = findingsById.get(e.findingId);
            const test = finding ? testsById.get(finding.testId) : undefined;
            return test ? matchWhereField(test.engagementId, nestedEngagementId) : false;
          });
        }
        return all;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeEvidenceRow = { id: nextId("evidence"), uploadedAt: new Date(), malwareStatus: "PENDING", malwareDetections: null, ...data };
        evidenceById.set(row.id, row);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...evidenceById.values()];
        if (where?.findingId) rows = rows.filter((e) => matchWhereField(e.findingId, where.findingId));
        for (const e of rows) evidenceById.delete(e.id);
        return { count: rows.length };
      }),
    },
    complianceCheck: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = complianceChecksById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: { clientId: engagementsById.get(row.engagementId)?.clientId } };
        return row;
      }),
      findMany: vi.fn(async ({ where, select }: any) => {
        let all = [...complianceChecksById.values()];
        if (where?.engagementId) all = all.filter((c) => matchWhereField(c.engagementId, where.engagementId));
        if (where?.framework) all = all.filter((c) => c.framework === where.framework);
        if (select) return all.map((c) => Object.fromEntries(Object.keys(select).map((k) => [k, (c as any)[k]])));
        return all;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeComplianceCheckRow = { id: nextId("compliance"), notesEnc: null, createdAt: new Date(), ...data };
        complianceChecksById.set(row.id, row);
        return row;
      }),
      createMany: vi.fn(async ({ data }: any) => {
        for (const d of data) {
          const row: FakeComplianceCheckRow = { id: nextId("compliance"), notesEnc: null, createdAt: new Date(), ...d };
          complianceChecksById.set(row.id, row);
        }
        return { count: data.length };
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = complianceChecksById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...complianceChecksById.values()];
        if (where?.engagementId) rows = rows.filter((c) => matchWhereField(c.engagementId, where.engagementId));
        for (const c of rows) complianceChecksById.delete(c.id);
        return { count: rows.length };
      }),
    },
    report: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = reportsById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: { clientId: engagementsById.get(row.engagementId)?.clientId } };
        return row;
      }),
      findMany: vi.fn(async ({ where, select }: any) => {
        let all = [...reportsById.values()];
        if (where?.engagementId) all = all.filter((r) => matchWhereField(r.engagementId, where.engagementId));
        if (where?.type) all = all.filter((r) => r.type === where.type);
        if (select) return all.map((r) => Object.fromEntries(Object.keys(select).map((k) => [k, (r as any)[k]])));
        return all;
      }),
      count: vi.fn(async ({ where }: any) => [...reportsById.values()].filter((r) => r.engagementId === where.engagementId && r.type === where.type).length),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeReportRow = { id: nextId("report"), generatedAt: new Date(), ...data };
        reportsById.set(row.id, row);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        let rows = [...reportsById.values()];
        if (where?.engagementId) rows = rows.filter((r) => matchWhereField(r.engagementId, where.engagementId));
        for (const r of rows) reportsById.delete(r.id);
        return { count: rows.length };
      }),
    },
    retest: {
      findMany: vi.fn(async ({ where }: any) => [...retestsById.values()].filter((r) => matchWhereField(r.findingId, where?.findingId))),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeRetestRow = { id: nextId("retest"), notesEnc: null, retestedAt: new Date(), ...data };
        retestsById.set(row.id, row);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...retestsById.values()].filter((r) => matchWhereField(r.findingId, where?.findingId));
        for (const r of rows) retestsById.delete(r.id);
        return { count: rows.length };
      }),
    },
    trainingSession: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = trainingSessionsById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: { clientId: engagementsById.get(row.engagementId)?.clientId } };
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => [...trainingSessionsById.values()].filter((t) => matchWhereField(t.engagementId, where?.engagementId))),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeTrainingSessionRow = { id: nextId("training"), customTopic: null, status: "SCHEDULED", attendeeCount: 0, notesEnc: null, ...data };
        trainingSessionsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = trainingSessionsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...trainingSessionsById.values()].filter((t) => matchWhereField(t.engagementId, where?.engagementId));
        for (const t of rows) trainingSessionsById.delete(t.id);
        return { count: rows.length };
      }),
    },
    scanJob: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = scanJobsById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: { clientId: engagementsById.get(row.engagementId)?.clientId } };
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => [...scanJobsById.values()].filter((s) => matchWhereField(s.engagementId, where?.engagementId))),
      findFirst: vi.fn(async ({ where }: any) => {
        const statusIn = where?.status?.in as string[] | undefined;
        return [...scanJobsById.values()].find((s) => s.assetId === where.assetId && (!statusIn || statusIn.includes(s.status))) ?? null;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeScanJobRow = {
          id: nextId("scanjob"),
          tool: "nuclei",
          status: "QUEUED",
          startedAt: null,
          completedAt: null,
          errorMessage: null,
          findingsCreated: 0,
          findingsSkipped: 0,
          createdAt: new Date(),
          rawResultEnc: null,
          ...data,
        };
        scanJobsById.set(row.id, row);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...scanJobsById.values()].filter((s) => matchWhereField(s.engagementId, where?.engagementId));
        for (const s of rows) scanJobsById.delete(s.id);
        return { count: rows.length };
      }),
    },
    discoveryJob: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = discoveryJobsById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: { clientId: engagementsById.get(row.engagementId)?.clientId } };
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => [...discoveryJobsById.values()].filter((j) => matchWhereField(j.engagementId, where?.engagementId))),
      findFirst: vi.fn(async ({ where }: any) => {
        const statusIn = where?.status?.in as string[] | undefined;
        return [...discoveryJobsById.values()].find((j) => j.assetId === where.assetId && (!statusIn || statusIn.includes(j.status))) ?? null;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeDiscoveryJobRow = {
          id: nextId("discoveryjob"),
          tool: "passive-discovery",
          status: "QUEUED",
          startedAt: null,
          completedAt: null,
          errorMessage: null,
          discoveredCount: null,
          createdAt: new Date(),
          ...data,
        };
        discoveryJobsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = discoveryJobsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...discoveryJobsById.values()].filter((j) => matchWhereField(j.engagementId, where?.engagementId));
        for (const j of rows) discoveryJobsById.delete(j.id);
        return { count: rows.length };
      }),
    },
    discoveredAsset: {
      findUnique: vi.fn(async ({ where, include }: any) => {
        const row = discoveredAssetsById.get(where.id);
        if (!row) return null;
        if (include?.engagement) return { ...row, engagement: { clientId: engagementsById.get(row.engagementId)?.clientId } };
        return row;
      }),
      findMany: vi.fn(async ({ where }: any) => {
        let all = [...discoveredAssetsById.values()];
        if (where?.engagementId) all = all.filter((d) => matchWhereField(d.engagementId, where.engagementId));
        if (where?.parentAssetId) all = all.filter((d) => matchWhereField(d.parentAssetId, where.parentAssetId));
        return all;
      }),
      create: vi.fn(async ({ data }: any) => {
        const row: FakeDiscoveredAssetRow = {
          id: nextId("discoveredasset"),
          openPorts: [],
          status: "NEW",
          promotedAssetId: null,
          reviewedBy: null,
          reviewedAt: null,
          createdAt: new Date(),
          ...data,
        };
        discoveredAssetsById.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: any) => {
        const row = discoveredAssetsById.get(where.id)!;
        Object.assign(row, data);
        return row;
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...discoveredAssetsById.values()].filter((d) => matchWhereField(d.engagementId, where?.engagementId));
        for (const d of rows) discoveredAssetsById.delete(d.id);
        return { count: rows.length };
      }),
    },
    keyRef: {
      create: vi.fn(async ({ data }: any) => {
        const row: FakeKeyRefRow = { id: nextId("keyref"), status: "ACTIVE", createdAt: new Date(), retiredAt: null, ...data };
        keyRefsById.set(row.id, row);
        return row;
      }),
      updateMany: vi.fn(async ({ where, data }: any) => {
        let rows = [...keyRefsById.values()];
        if (where?.status) rows = rows.filter((k) => k.status === where.status);
        for (const k of rows) Object.assign(k, data);
        return { count: rows.length };
      }),
      deleteMany: vi.fn(async ({ where }: any) => {
        const rows = [...keyRefsById.values()].filter((k) => matchWhereField(k.resourceId, where?.resourceId));
        for (const k of rows) keyRefsById.delete(k.id);
        return { count: rows.length };
      }),
    },
    auditLog: {
      create: vi.fn(async ({ data }: any) => {
        const row: FakeAuditLogRow = { id: nextId("audit"), engagementId: null, timestamp: new Date(), ...data };
        auditLogs.push(row);
        return row;
      }),
      count: vi.fn(async (args: any = {}) => {
        const { where } = args;
        if (!where) return auditLogs.length;
        return auditLogs.filter((l) => {
          if (where.result && l.result !== where.result) return false;
          if (where.timestamp?.gte && l.timestamp < where.timestamp.gte) return false;
          return true;
        }).length;
      }),
      findMany: vi.fn(async ({ where, take }: any = {}) => {
        let all = [...auditLogs].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        if (where?.resourceType) all = all.filter((l) => l.resourceType === where.resourceType);
        if (where?.resourceId) all = all.filter((l) => l.resourceId === where.resourceId);
        if (where?.userId) all = all.filter((l) => l.userId === where.userId);
        return typeof take === "number" ? all.slice(0, take) : all;
      }),
    },
    $transaction: vi.fn(async (opsOrFn: any) => {
      if (typeof opsOrFn === "function") return opsOrFn(prismaMock);
      return Promise.all(opsOrFn);
    }),
};

vi.mock("../../src/db/prisma", () => ({
  prisma: prismaMock,
}));

/** Directly seeds a user row, bypassing the API — for test setup only. */
export function seedUser(row: Omit<FakeUserRow, "id" | "createdAt" | "lastLoginAt"> & Partial<Pick<FakeUserRow, "id">>): FakeUserRow {
  const full: FakeUserRow = { id: row.id ?? nextId("user"), createdAt: new Date(), lastLoginAt: null, ...row };
  usersByEmail.set(full.email, full);
  return full;
}

export function seedClient(row: Partial<FakeClientRow> & { id: string; name: string }): FakeClientRow {
  const full: FakeClientRow = { industry: null, primaryContactEnc: null, billingInfoEnc: null, createdAt: new Date(), kmsKeyId: null, ...row };
  clientsById.set(full.id, full);
  return full;
}

export function seedEngagement(row: Partial<FakeEngagementRow> & { id: string; clientId: string }): FakeEngagementRow {
  const full: FakeEngagementRow = {
    status: "SCOPING",
    assumptionsEnc: null,
    exclusionsEnc: null,
    authorizedBy: null,
    authorizationSignedAt: null,
    authorizationDocRef: null,
    authorizationDocIv: null,
    authorizationDocAuthTag: null,
    authorizationDocEncryptedDataKey: null,
    authorizationDocKmsKeyId: null,
    authorizationDocKeyVersion: null,
    authorizationMethod: null,
    authorizationEnvelopeId: null,
    authorizationRequestStatus: null,
    createdAt: new Date(),
    ...row,
  };
  engagementsById.set(full.id, full);
  return full;
}

export function seedAsset(row: Partial<FakeAssetRow> & { id: string; engagementId: string; type: string; name: string }): FakeAssetRow {
  const full: FakeAssetRow = {
    owner: null,
    criticality: "MEDIUM",
    inScope: true,
    identifierEnc: null,
    notesEnc: null,
    verificationStatus: "UNVERIFIED",
    verificationMethod: null,
    verificationToken: null,
    verifiedAt: null,
    verifiedBy: null,
    createdAt: new Date(),
    ...row,
  };
  assetsById.set(full.id, full);
  return full;
}

export function seedTest(row: Partial<FakeTestRow> & { id: string; engagementId: string; assetId: string; type: string; testerId: string }): FakeTestRow {
  const full: FakeTestRow = { methodology: null, toolUsed: null, status: "PLANNED", completedAt: null, ...row };
  testsById.set(full.id, full);
  return full;
}

export function seedFinding(row: Partial<FakeFindingRow> & { id: string; testId: string; assetId: string; title: string; severity: string }): FakeFindingRow {
  const full: FakeFindingRow = {
    cvssScore: null,
    descriptionEnc: null,
    reproductionStepsEnc: null,
    remediationGuidanceEnc: null,
    status: "OPEN",
    remediationEffort: null,
    discoveredAt: new Date(),
    aiRemediationDraftEnc: null,
    aiFalsePositiveLikelihood: null,
    aiTriageRationaleEnc: null,
    aiTriagedAt: null,
    ...row,
  };
  findingsById.set(full.id, full);
  return full;
}

/**
 * Test-only introspection: reads a finding's raw stored row, including its
 * `*Enc` fields — the real API never returns these, so per-tenant-key tests
 * (verifying which kmsKeyId a field actually encrypted under) need direct
 * access rather than going through a route response.
 */
export function getRawFinding(id: string): FakeFindingRow | undefined {
  return findingsById.get(id);
}

export function seedEvidence(
  row: Partial<FakeEvidenceRow> & { id: string; findingId: string; originalFilename: string; storageKey: string }
): FakeEvidenceRow {
  const full: FakeEvidenceRow = {
    mimeType: "application/octet-stream",
    iv: "",
    authTag: "",
    encryptedDataKey: "",
    kmsKeyId: "test-cmk",
    keyVersion: 1,
    sizeBytes: 0,
    uploadedBy: "user_1",
    sha256: "0".repeat(64),
    uploadedAt: new Date(),
    malwareStatus: "PENDING",
    malwareDetections: null,
    ...row,
  };
  evidenceById.set(full.id, full);
  return full;
}

export function seedRetest(row: Partial<FakeRetestRow> & { id: string; findingId: string; retestedBy: string; result: string }): FakeRetestRow {
  const full: FakeRetestRow = { notesEnc: null, retestedAt: new Date(), ...row };
  retestsById.set(full.id, full);
  return full;
}

export function seedComplianceCheck(
  row: Partial<FakeComplianceCheckRow> & { id: string; engagementId: string; framework: string; controlId: string; controlName: string }
): FakeComplianceCheckRow {
  const full: FakeComplianceCheckRow = { status: "PENDING", notesEnc: null, createdAt: new Date(), ...row };
  complianceChecksById.set(full.id, full);
  return full;
}

export function seedReport(row: Partial<FakeReportRow> & { id: string; engagementId: string; type: string }): FakeReportRow {
  const full: FakeReportRow = {
    version: 1,
    storageKey: `reports/${row.id}`,
    iv: "",
    authTag: "",
    encryptedDataKey: "",
    kmsKeyId: "test-cmk",
    keyVersion: 1,
    generatedBy: "user_1",
    generatedAt: new Date(),
    ...row,
  };
  reportsById.set(full.id, full);
  return full;
}

export function seedTrainingSession(row: Partial<FakeTrainingSessionRow> & { id: string; engagementId: string; topic: string }): FakeTrainingSessionRow {
  const full: FakeTrainingSessionRow = {
    customTopic: null,
    scheduledAt: new Date(),
    status: "SCHEDULED",
    attendeeCount: 0,
    notesEnc: null,
    ...row,
  };
  trainingSessionsById.set(full.id, full);
  return full;
}

export function seedScanJob(row: Partial<FakeScanJobRow> & { id: string; engagementId: string; assetId: string; testId: string }): FakeScanJobRow {
  const full: FakeScanJobRow = {
    tool: "nuclei",
    status: "QUEUED",
    startedAt: null,
    completedAt: null,
    errorMessage: null,
    findingsCreated: 0,
    findingsSkipped: 0,
    createdAt: new Date(),
    rawResultEnc: null,
    ...row,
  };
  scanJobsById.set(full.id, full);
  return full;
}

export function seedDiscoveryJob(
  row: Partial<FakeDiscoveryJobRow> & { id: string; engagementId: string; assetId: string }
): FakeDiscoveryJobRow {
  const full: FakeDiscoveryJobRow = {
    tool: "passive-discovery",
    status: "QUEUED",
    startedAt: null,
    completedAt: null,
    errorMessage: null,
    discoveredCount: null,
    createdAt: new Date(),
    ...row,
  };
  discoveryJobsById.set(full.id, full);
  return full;
}

export function seedDiscoveredAsset(
  row: Partial<FakeDiscoveredAssetRow> & { id: string; engagementId: string; parentAssetId: string; discoveryJobId: string }
): FakeDiscoveredAssetRow {
  const full: FakeDiscoveredAssetRow = {
    valueEnc: null,
    source: "crt.sh",
    openPorts: [],
    status: "NEW",
    promotedAssetId: null,
    reviewedBy: null,
    reviewedAt: null,
    createdAt: new Date(),
    ...row,
  };
  discoveredAssetsById.set(full.id, full);
  return full;
}

/** Wipes all fake data between tests so one test's seed data can't leak into another. */
export function resetFakeDb(): void {
  usersByEmail.clear();
  clientsById.clear();
  engagementsById.clear();
  assetsById.clear();
  testsById.clear();
  findingsById.clear();
  evidenceById.clear();
  complianceChecksById.clear();
  reportsById.clear();
  retestsById.clear();
  trainingSessionsById.clear();
  scanJobsById.clear();
  discoveryJobsById.clear();
  discoveredAssetsById.clear();
  keyRefsById.clear();
  auditLogs.length = 0;
}

/** The header value that authenticates a supertest request as the given (pre-seeded) user's email. */
export function authHeader(email: string): string {
  return email;
}
