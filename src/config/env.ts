import "dotenv/config";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

const kmsProvider = (process.env.KMS_PROVIDER ?? "local") as "local" | "aws";
const threatResponseProvider = (process.env.THREAT_RESPONSE_PROVIDER ?? "noop") as "noop" | "crowdstrike";
const esignatureProvider = (process.env.ESIGNATURE_PROVIDER ?? "noop") as "noop" | "documenso";
const aiTriageProvider = (process.env.AI_TRIAGE_PROVIDER ?? "noop") as "noop" | "anthropic";

export const env = {
  port: parseInt(process.env.PORT ?? "4000", 10),
  databaseUrl: required("DATABASE_URL"),

  // Comma-separated list of origins allowed to call this API (e.g. the
  // deployed frontend's URL). Unset in dev, where the Vite proxy means the
  // browser never sends a cross-origin request in the first place; must be
  // set before a real deployment, or every origin is rejected (see app.ts).
  corsOrigins: process.env.CORS_ORIGINS?.split(",").map((s) => s.trim()).filter(Boolean) ?? [],

  // Object storage backend for encrypted evidence/reports. "supabase" (default)
  // uses a private Supabase Storage bucket via the service_role key; "local"
  // writes ciphertext to STORAGE_DIR on disk (offline dev/tests only).
  storageBackend: (process.env.STORAGE_BACKEND ?? "supabase") as "supabase" | "local",
  storageDir: process.env.STORAGE_DIR ?? "./storage",
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
  supabaseStorageBucket: process.env.SUPABASE_STORAGE_BUCKET ?? "jupiter-evidence",

  // Which KmsProvider src/crypto/index.ts constructs. "local" (default) is
  // the dev-only stand-in in src/crypto/kms.ts; "aws" uses a real KMS key via
  // src/crypto/providers/aws-kms.ts. Each pulls in its own required vars below
  // — only the ones for the selected provider are validated at startup.
  kmsProvider,

  // Local-dev KMS stand-in config — see src/crypto/kms.ts. Only required
  // when that's actually the selected provider.
  cmkBase64: kmsProvider === "local" ? required("CMK_BASE64") : process.env.CMK_BASE64,
  cmkId: process.env.CMK_ID ?? "local-cmk",
  cmkVersion: parseInt(process.env.CMK_VERSION ?? "1", 10),

  // Real AWS KMS config — only required when KMS_PROVIDER=aws.
  awsRegion: kmsProvider === "aws" ? required("AWS_REGION") : process.env.AWS_REGION,
  awsKmsKeyId: kmsProvider === "aws" ? required("AWS_KMS_KEY_ID") : process.env.AWS_KMS_KEY_ID,
  awsKmsKeyVersion: parseInt(process.env.AWS_KMS_KEY_VERSION ?? "1", 10),
  // Optional — only set on platforms (Vercel/Lambda) where AWS_ACCESS_KEY_ID/
  // AWS_SECRET_ACCESS_KEY/AWS_REGION are reserved names the platform
  // silently shadows with its own execution sandbox's values at runtime (see
  // aws-kms.ts) — confirmed live: AWS_REGION on Vercel resolves to Vercel's
  // own region code, not whatever's configured. All three travel together,
  // deliberately outside the AWS_* reserved prefix. Omit entirely on a real
  // EC2/IAM-instance-role host — the default credential chain and AWS_REGION
  // both work correctly there already.
  awsKmsStaticAccessKeyId: process.env.AWS_KMS_STATIC_ACCESS_KEY_ID,
  awsKmsStaticSecretAccessKey: process.env.AWS_KMS_STATIC_SECRET_ACCESS_KEY,
  awsKmsStaticRegion: process.env.AWS_KMS_STATIC_REGION,

  // Shared secret for POST /internal/rotate-keys (scheduled key rotation).
  // Unset by default — the route refuses every request unless this is set,
  // rather than silently allowing unauthenticated rotation calls.
  cronSecret: process.env.CRON_SECRET,

  // Website scanning (src/modules/scanning) — see README "Website scanning".
  // Requires the Nuclei binary on PATH (or an explicit path here) on
  // whatever host actually runs this process; not usable on Vercel's
  // serverless runtime (no persistent binary, no long-running process).
  nucleiBinPath: process.env.NUCLEI_BIN_PATH ?? "nuclei",
  // Safety default: refuse to scan a target that resolves to a private/
  // loopback/link-local address, so a mistyped or malicious asset URL can't
  // turn this feature into an SSRF probe of the server's own network. Only
  // flip this on for local dev/demo use against your own machine.
  allowInternalScanTargets: process.env.ALLOW_INTERNAL_SCAN_TARGETS === "true",

  // Attack surface discovery's port enrichment (src/modules/discovery/nmap.ts)
  // — service/version detection (-sV) on whatever a discovery run finds
  // live, replacing the earlier bare connect-only check. Same deployment
  // constraint as Nuclei above: needs the binary on PATH on a persistent
  // host, not usable on Vercel's serverless runtime. Missing/unreachable
  // binary degrades a discovery run to "no port detail" rather than
  // failing it — see nmap.ts.
  nmapBinPath: process.env.NMAP_BIN_PATH ?? "nmap",

  // Malware/threat-intel checks (src/integrations/virustotal.ts) — evidence
  // file hash lookups and scanned-domain reputation. Entirely optional: unset
  // means every check reports "unavailable" rather than failing anything.
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,

  // Active response (src/threat-response) — "noop" (default) takes no action
  // and says so; "crowdstrike" calls a real EDR API to request host network
  // containment. Always a human-triggered action (POST .../response-actions/
  // contain), never automatic.
  threatResponseProvider,
  crowdStrikeClientId: threatResponseProvider === "crowdstrike" ? required("CROWDSTRIKE_CLIENT_ID") : process.env.CROWDSTRIKE_CLIENT_ID,
  crowdStrikeClientSecret:
    threatResponseProvider === "crowdstrike" ? required("CROWDSTRIKE_CLIENT_SECRET") : process.env.CROWDSTRIKE_CLIENT_SECRET,
  crowdStrikeBaseUrl: process.env.CROWDSTRIKE_BASE_URL ?? "https://api.crowdstrike.com",

  // E-signature (src/esignature) — "noop" (default) means the authorization
  // gate stays purely manual/self-attested (POST /engagements/:id/authorize);
  // "documenso" sends the ROE out for a real, verifiable signature instead.
  esignatureProvider,
  documensoApiKey: esignatureProvider === "documenso" ? required("DOCUMENSO_API_KEY") : process.env.DOCUMENSO_API_KEY,

  // Notifications (src/notifications) — fan-out, not a single "provider"
  // selection: each just needs its own env vars set to turn on, and any
  // combination (none, either, or both) is valid. A CRITICAL/HIGH finding
  // from any creation path triggers whichever are configured.
  slackWebhookUrl: process.env.SLACK_WEBHOOK_URL,
  resendApiKey: process.env.RESEND_API_KEY,
  notificationEmailFrom: process.env.NOTIFICATION_EMAIL_FROM,
  notificationEmailTo: process.env.NOTIFICATION_EMAIL_TO,

  // AI-assisted triage (src/ai) — "noop" (default) drafts nothing;
  // "anthropic" calls the Claude Messages API to draft remediation guidance
  // and a false-positive likelihood per finding. Always advisory: writes
  // only to Finding.aiRemediationDraftEnc/aiFalsePositiveLikelihood, never
  // to the real remediationGuidance/status a human owns — see src/ai/provider.ts.
  aiTriageProvider,
  anthropicApiKey: aiTriageProvider === "anthropic" ? required("ANTHROPIC_API_KEY") : process.env.ANTHROPIC_API_KEY,
  aiTriageModel: process.env.AI_TRIAGE_MODEL ?? "claude-sonnet-5",

  // Hard per-org budget caps on real AI calls (src/ai/budget.ts) — checked
  // and recorded (AiUsageRecord) before every real Anthropic call across
  // triage, NL querying, and attack-path narration. DB-backed on purpose,
  // not express-rate-limit's in-memory counters: this app runs on Vercel
  // serverless, where in-memory state doesn't survive a cold start, so an
  // in-memory cap would silently reset and stop actually capping anything.
  // Meaningless (and skipped entirely) while AI_TRIAGE_PROVIDER=noop, since
  // nothing costs money to cap yet — exists so the caps are already in
  // place *before* anyone flips that switch, not added under pressure
  // after a surprise bill.
  aiDailyCallCap: parseInt(process.env.AI_DAILY_CALL_CAP ?? "200", 10),
  aiMonthlyCallCap: parseInt(process.env.AI_MONTHLY_CALL_CAP ?? "3000", 10),

  // Error tracking (src/config/sentry.ts) — unset means errors only go to
  // the pino logs on this machine, same as always; set it to also get every
  // unhandled exception/rejection and every 500 reported to Sentry.
  sentryDsn: process.env.SENTRY_DSN,
};
