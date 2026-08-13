# Jupiter

A one-time cybersecurity assessment platform: discovery/scoping, vulnerability
assessment (manual or bulk-imported from scanner output), authorized
pen-testing, compliance review against a standard control library,
prioritized remediation roadmaps, staff security-awareness training,
executive + technical reporting, and retesting — with AES-256 encryption for
all stored assessment data (findings, evidence, reports) and application-layer
key management, RBAC, and audit logging.

Everything in the original service brief is implemented now, including
in-app automated scanning (see "Website scanning") and e-signature
authorization (see "Authorization gate") — both were originally scoped out
and added later; "Deferred to v2" tracks what's still genuinely out of
scope (mainly: anything more aggressive than non-intrusive automated
scanning, which is a deliberate line, not a gap).

Handing this to a client's team? Start with `docs/client-onboarding.md` —
a short, non-technical walkthrough of what they'll see and who on their
side should be looking at what.

## Stack

- Node.js + TypeScript + Express
- PostgreSQL via Prisma, hosted on Supabase (project "demi", ref `rwrkimrznijzxcuaudbd`)
- AES-256-GCM envelope encryption (`src/crypto`), with a swappable KMS boundary —
  `LocalKmsProvider` (dev) or a real `AwsKmsProvider`, selected via `KMS_PROVIDER`
- Encrypted evidence/report files in a private Supabase Storage bucket (`jupiter-evidence`) by default, swappable for local disk or S3/GCS/Azure Blob
- Clerk for identity/credentials/MFA/sessions; this app's own `User` table for authorization (role, org) — see "Authentication" below
- Role-based access control, append-only audit log
- Configurable CORS allowlist, structured JSON logging (`pino`)
- Scheduled key rotation (`GET /internal/rotate-keys`, wired to Vercel Cron)
- In-app website scanning (Nuclei) with ownership verification, and optional
  malware detection (VirusTotal) + human-triggered active response (EDR)
- React + TypeScript + Vite operator dashboard (`frontend/`)
- Starting-point legal templates (`templates/legal/`) — MSA, ROE/SOW, NDA, DPA

## Getting started

The schema is already applied to Supabase and RLS is enabled (deny-by-default —
Prisma's direct Postgres connection bypasses it; the `anon`/`authenticated`
API roles cannot read or write any of these tables). You still need to:

```bash
cp .env.example .env
```

Then fill in, per the comments in `.env.example`:

- `DATABASE_URL` — from the Supabase dashboard (Project Settings -> Database ->
  Connection string). The DB password can't be read back through tooling; set
  or reset it there and paste the full URL.
- `SUPABASE_SERVICE_ROLE_KEY` — from Project Settings -> API. Used only
  server-side to read/write the private evidence/reports bucket; never expose
  it to a browser.
- `CLERK_SECRET_KEY` and `CLERK_PUBLISHABLE_KEY` — from the Clerk dashboard
  (API Keys). Also set `VITE_CLERK_PUBLISHABLE_KEY` (same publishable key) in
  `frontend/.env`.
- `CMK_BASE64` — generation command is in `.env.example`.
- In `frontend/.env`, also set `VITE_SUPABASE_URL` and
  `VITE_SUPABASE_PUBLISHABLE_KEY` (Supabase dashboard -> Project Settings ->
  API -> the `sb_publishable_...` key, **not** `service_role`) — needed for
  presigned evidence uploads (see "Presigned evidence uploads" below); the
  file-upload UI falls back to the older multipart route without it, so
  it's not a hard requirement to get the app running, just to exercise that
  path.

```bash
npm install
npm run prisma:generate       # generates the Prisma client against the existing schema
SEED_ADMIN_EMAIL="you@example.com" npm run seed   # provisions a security_admin User row for a real email
npm run dev                   # starts the API on :4000
```

`npm run seed` doesn't create a login — it creates the authorization-side
`User` row (role, org). Sign up in Clerk (frontend `/login`) using **the
exact same email** you passed as `SEED_ADMIN_EMAIL`; `requireAuth`
(`src/middleware/auth.ts`) resolves signed-in Clerk users to this table by
email. See "Authentication" below.

Migration history is baselined (`_prisma_migrations` exists and
`20260806000000_init_jupiter_schema`, `20260806170000_add_mfa_secret`,
`20260806190000_roadmap_compliance_training`, and
`20260806210000_clerk_auth_drop_password_mfa` are all recorded as applied).
**`prisma migrate dev`/`deploy` hang indefinitely
against this database** — Prisma's schema engine needs a session-mode
connection, and this project's `DATABASE_URL` is Supabase's *transaction*
pooler (`pgbouncer=true`, required for the query engine — the app's actual
runtime path — to work at all through it). For a new migration: write the
SQL by hand under `prisma/migrations/<timestamp>_<name>/migration.sql`
(matching Prisma's own format), then apply it with `prisma.$executeRawUnsafe`
via a one-off script using the regular Prisma Client (which *does* work fine
through this pooler) and insert a matching row into `_prisma_migrations`
yourself — see the git history around the `add_mfa_secret` migration for a
worked example of exactly this. Regenerate the client afterward either way
(`npm run prisma:generate`).

Prefer to run fully offline instead (no Supabase account needed)? Set
`STORAGE_BACKEND=local` in `.env`, point `DATABASE_URL` at `docker compose up -d`
(starts a local Postgres via `docker-compose.yml`), and skip the Supabase-only
env vars.

Run the test suite — crypto (round-trip, tamper-detection, AAD-binding, cross-key
failure) and RBAC/org-scoping (`assertOwnOrg`, `requireRole`, both unit-tested
against mocked Prisma rather than the live DB):

```bash
npm test
```

Sign in through the frontend (`/login`) with the email you seeded — Clerk
handles the credential/session flow, and the browser SDK attaches a fresh
token to every API request automatically (see "Authentication" below).

## How the encryption works

Every sensitive field (`*Enc` columns in `prisma/schema.prisma`) and every
uploaded file (evidence, generated reports) goes through envelope encryption:

1. `src/crypto/kms.ts` defines the `KmsProvider` interface. `KMS_PROVIDER`
   (env var, default `local`) selects which one `src/crypto/index.ts`
   constructs — the only place in the app that does:
   - `local` — `LocalKmsProvider` wraps a per-record Data Encryption Key
     (DEK) with a Customer Master Key read from `CMK_BASE64`. Dev-only stand-in.
   - `aws` — `AwsKmsProvider` (`src/crypto/providers/aws-kms.ts`), a real,
     installed KMS provider using `@aws-sdk/client-kms`. Requires
     `AWS_REGION` and `AWS_KMS_KEY_ID`. **Untested against a live AWS
     account** (no credentials available in this environment to verify it) —
     it's ordinary AWS SDK v3 usage against `GenerateDataKey`/`Decrypt`, but
     confirm it against your own account before trusting it with real client
     data. The execution role needs exactly those two KMS permissions on the
     one key ARN, nothing else (see the file for why).
   - A GCP KMS / Azure Key Vault / HashiCorp Vault provider would follow the
     same pattern — implement `KmsProvider`, add a third `KMS_PROVIDER` branch.
2. `src/crypto/envelope.ts` (`encryptField`/`decryptField` for DB columns,
   `encryptBuffer`/`decryptBuffer` for files) generates a fresh DEK per write,
   encrypts with AES-256-GCM, binds ciphertext to its record via an AAD
   context string (e.g. `finding:1234:description`), then wipes the DEK from
   memory. Nothing in the app ever persists a raw key.
3. `src/crypto/rotation.ts` re-wraps a record's DEK under the current CMK
   version without ever exposing key material outside the crypto module.
   `rotateAllFields()` walks every encrypted column across every table
   (batched, 25 rows/table/run) and rotates any whose embedded
   keyVersion/kmsKeyId doesn't match the provider's current key — this is
   the actual scheduled job, exposed at `GET /internal/rotate-keys`
   (protected by `CRON_SECRET`, checked against the `Authorization: Bearer`
   header Vercel Cron sends automatically when that env var exists) and
   wired to run daily via `vercel.json`'s `crons` entry. Verified live: bumping
   `CMK_VERSION` and running the sweep correctly rotated every field that had
   data (including a user's MFA secret), and every rotated record — findings,
   assets, training notes, the MFA secret itself — remained correctly
   decryptable afterward, confirmed by re-fetching each one and, for the MFA
   case, actually logging in with a fresh code generated post-rotation.
4. `KeyRef` rows (`prisma/schema.prisma`) are a metadata ledger only (which
   KMS key/version protects which record) — never raw keys — used for
   rotation bookkeeping and audit.
5. Files: `src/crypto/storage.ts` defines `ObjectStorage`. By default
   `SupabaseObjectStorage` (`src/crypto/providers/supabase-storage.ts`) uploads
   already-encrypted bytes to a private Supabase Storage bucket using the
   service_role key (bypasses the bucket's RLS, same trust boundary as the
   direct Postgres connection). Set `STORAGE_BACKEND=local` to use
   `LocalObjectStorage` (disk) instead for offline dev/tests. Either way,
   swapping providers happens in exactly one place: `src/crypto/index.ts`.

## Per-tenant encryption keys

Jupiter's third addition beyond Enforcer's original scope, and the one with
the most direct enterprise-sales relevance: every client can be moved from
the shared system key everyone started on onto a dedicated key of their
own — no other tenant's data is ever wrapped by it. Requires **zero new
environment variables** — it's built entirely on the envelope-encryption
mechanism above, not a parallel system.

**How it fits the existing design.** `Client.kmsKeyId` (`prisma/schema.prisma`)
is `null` by default — every client behaves exactly as before until an
admin calls `PATCH /clients/:id/kms-key { "kmsKeyId": "..." }`. From that
point on, `src/crypto/tenant.ts`'s `tenantKms(clientId)` resolves a
`KmsProvider` pinned to that client's key for every *new* encryption — new
findings, new assets, new evidence, new reports, everything under that
client. Nothing about `encryptField`/`decryptField`/`encryptBuffer`/
`decryptBuffer` changed: `tenantKms()` returns an ordinary `KmsProvider`,
so every call site just swaps which instance it passes in, the same object
shape the whole crypto module already used everywhere.

**Decrypting never needs to know a record's tenant.** This is the property
that keeps the migration both correct and small: `EncryptedField.kmsKeyId`
already travels with every record (it has to, to support key rotation), so
`decryptField(kms, field, aad)` resolves the right unwrapping key from
`field.kmsKeyId` regardless of which `KmsProvider` instance is passed in —
tenant-scoped or the plain system one. Concretely, this means **every
decrypt call site in the app needed zero changes** — only the ~15 `encrypt`
call sites that create new records did (`src/modules/*/`), each swapping
`kms` for `await tenantKms(clientId)` using whatever `clientId` that route
already resolves for its own `assertOwnOrg` check.

**Not a forced re-encryption.** Assigning a client a key doesn't touch
their existing data — old records keep decrypting exactly as before,
whatever key they were originally wrapped under. This is the same
principle key rotation already relies on, not a new one. (`rotateAllFields()`
was updated to skip — not silently re-wrap — any record already on a
non-system key, so the nightly rotation sweep can never undo a tenant-key
assignment; genuinely rotating a *tenant's own* key to a new version is
real, separate future work, tracked below.)

**How the two KMS providers implement it:**

- **`LocalKmsProvider` (dev)** derives a distinct 32-byte subkey per
  `keyId` from the one root CMK via HKDF-SHA256 — no separate key
  provisioning needed to exercise or test this feature locally. The system
  default key (no `keyId` passed) still uses the raw CMK unchanged, so this
  is fully backward compatible with every record encrypted before this
  feature existed. **Live-verified in this environment** (not just
  "should work"): `tests/crypto.test.ts` proves a DEK wrapped under one
  tenant's derived key genuinely fails to unwrap under a different
  tenant's keyId or the system default, and `tests/routes/clients.test.ts`
  proves it end to end through the real API — two clients, two assigned
  keys, two findings created through the ordinary `POST .../findings`
  route, each finding's `descriptionEnc.kmsKeyId` provably different and
  each still decrypting correctly through the ordinary `GET /findings/:id`
  route.
- **`AwsKmsProvider` (production)** passes the assigned `kmsKeyId` straight
  through as the `KeyId` on `GenerateDataKeyCommand` — a real,
  separately-provisioned AWS KMS key ARN/alias, exactly like the existing
  system key. The app **never creates KMS keys itself** (see the IAM note
  in `src/crypto/providers/aws-kms.ts`); provisioning each tenant's key is
  infra work (Terraform/console), done once per client before assigning it
  via the PATCH endpoint. Inherits this provider's existing "untested
  against a live AWS account" caveat (see "Deferred to v2" below) — the
  per-tenant code path is ordinary parameterized `GenerateDataKeyCommand`
  usage, same SDK call the system key already makes, just confirm it
  against your own account.

**Deliberately out of scope for this pass:** the app doesn't provision AWS
KMS keys (infra work, not app code); there's no bulk "migrate all of
client X's existing data onto their new key" job (would reuse
`rotation.ts`'s walk-every-table machinery, scoped to one client, but
wasn't built — assigning a key only affects what's encrypted from that
point forward); and rotating a *tenant's own* key to a new version isn't
implemented (`rotateFieldKey` currently just skips non-system-key records
rather than rotating them in place).

## RBAC

Three roles (`prisma/schema.prisma` `Role` enum):

- `SECURITY_ADMIN` — internal staff. Full read/write on engagements they're assigned to; only role that can view `/audit-logs`.
- `TECHNICAL_CLIENT` — client-side technical staff. Full read on their org's findings/evidence/technical report.
- `EXEC_CLIENT` — client-side executives. Sees severity/status/title and the executive report only — no raw findings text, no evidence files (see `findings.routes.ts`, `evidence.routes.ts`).

Client-side users are scoped to their own `orgId` (`assertOwnOrg` in `src/middleware/rbac.ts`); `SECURITY_ADMIN` is exempt.

## Access control: invite-only, not public sign-up

Two layers, both real, both live-verified against the actual Clerk project
(not just configured and hoped-for):

1. **Clerk's "Restricted" sign-up mode is enabled at the instance level**
   (`allowlist: true`, set via `clerkClient.instance.updateRestrictions()`)
   — nobody can create a Clerk account at all unless they're on the
   allowlist or have a pending invitation. This isn't scoped to internal
   staff only: this Clerk instance serves client accounts
   (`technical_client`/`exec_client`) too, so the restriction has to cover
   the whole instance, not just an admin team.
2. **`POST /users`** (`src/modules/users/users.routes.ts`, `security_admin`
   only) is the one action that grants someone real access — it creates
   the authorization-side `User` row (role, org) *and* sends a real Clerk
   invitation (`clerkClient.invitations.createInvitation`) in the same
   call, so provisioning someone is one step, not two dashboards to keep
   in sync by hand. `GET /users` lists the current team; `DELETE
   /users/:id` revokes access immediately (deletes the row `requireAuth`
   depends on — a mid-session user gets 403'd on their next request) but
   deliberately doesn't touch the Clerk account itself, since deleting
   identity is a more sensitive, less-reversible action better left to an
   explicit dashboard step if truly needed; it also can't be used to
   remove your own access. A `Team` page (`frontend/src/pages/team`)
   wraps this for `security_admin` accounts, linked from the sidebar.

**Why not Clerk Organizations** (the more commonly-suggested pattern for
this): Jupiter's own `User.role` already answers "what can this person
do" — Organizations would only add "can this person get in at all," which
Clerk's Restricted/allowlist mode already answers without introducing a
second membership system that could drift out of sync with the first. One
authorization model, not two.

Verified live against the real project: enabled the restriction (with the
two real existing admin emails pre-allowlisted first, specifically so
enabling it couldn't lock out an active account), confirmed the existing
admin session kept working afterward, then exercised the full `/users`
surface for real — listed the team, rejected a duplicate email (409),
rejected a client-role invite with no org (400), deleted two stale demo
rows (204, including confirming self-removal is blocked), and sent a real
Clerk invitation email (`invitationSent: true`) to a safe `+alias` address
rather than an unknown third party.

## Security overview page

`/security` (`GET /security/status`, `security_admin` only) is a live
status board of every hardening control actually protecting the running
deployment — a trust-center page, not a settings page. Every field is
read fresh on load, nothing is hardcoded as "on": encryption (KMS provider,
CMK version, rotation), access control (Clerk's actual current restriction
state — one more live Clerk Backend API read, `updateRestrictions({})`
with an empty body, verified live to be a safe no-op read rather than a
reset), scanning guardrails (the private-target block, non-intrusive-only
scanning), detection/alerting (VirusTotal, Slack, Resend), active response
(CrowdStrike), and a live audit-event count.

The page scores six of these as a "defense in depth" posture indicator —
deliberately not a fake 100%: a dev/demo environment scoring 4/6 (no real
KMS yet, no malware detection configured) is the page doing its job
honestly, not a bug to hide. Built within the app's existing design
system (`Card`/`DarkCard`/`ProgressRing`/`Pill`, the same ink/paper/risk
color tokens as everywhere else) rather than introducing a new visual
language for one page.

## Findings trend across engagements

`GET /clients/:id/findings-history` (`clients.routes.ts`) is what makes a
retainer worth more than a series of one-off assessments: it aggregates
every finding across every engagement for a client and answers two
questions a single engagement's data can't — is risk trending up or down,
and is the same issue coming back unfixed between assessments.

- **By severity / by status** — a plain count breakdown across everything.
- **Recurring** — the same asset+title appearing in *more than one*
  engagement. This is deliberately different from "still open" (which just
  means one engagement hasn't finished remediating it yet) — recurring
  means it showed up again in a *later, separate* engagement, i.e. it
  wasn't actually fixed between assessments.
- **By engagement** — severity counts per engagement, ordered chronologically,
  rendered as a stacked bar chart on the client page (`FindingsTrend.tsx`)
  so a rising/falling trend is visible at a glance.

Metadata-only (title/severity/status/assetId, no `*Enc` field touched),
same as the per-engagement findings list — visible to every role including
`exec_client` without any extra gating. Verified live against the real demo
client's data (7 findings, 1 engagement, correctly showing 0 recurring —
recurrence requires 2+ engagements, which this account doesn't have yet).

## Engagement status tracker

The Overview tab (`StageTracker.tsx`) shows every engagement's progress as
seven stages: Scoping → Authorized → Testing → Findings identified →
Remediation → Retested → Report delivered. This is specifically what gives
`exec_client` a reason to log in themselves rather than waiting on an
update — every endpoint it calls (`tests`, `findings`, `reports`) is
already something that role can read.

Deliberately **not** a manually-set "current stage" field — that drifts out
of sync with reality the moment someone forgets to update it. Each stage is
derived live from data that already exists: `authorized` from
`authorizationSignedAt`, `testing` from whether any `Test` exists,
`findings`/`remediation`/`retested` from finding statuses, `delivered` from
whether a `Report` exists. It can never claim a stage is done that isn't,
because there's nothing to hand-maintain.

## Authentication

Identity, credentials, MFA, and sessions are handled entirely by
[Clerk](https://clerk.com) — this app no longer stores a password or a TOTP
secret for anyone. Jupiter's own Postgres only keeps the authorization side:
a `User` row (`name`, `email`, `role`, `orgId`) that a Clerk-verified request
gets resolved to.

- **Backend** — `clerkMiddleware()` is mounted globally (`src/app.ts`) and
  attaches Clerk's session state to every request. `requireAuth`
  (`src/middleware/auth.ts`) reads it via `getAuth(req)`, looks up the
  signed-in user's email through `clerkClient.users.getUser()`, and finds the
  matching `User` row by email. That row's `id`/`role`/`orgId` become
  `req.user` — the exact shape the rest of the app (`requireRole`,
  `assertOwnOrg`, every route handler) already expected, so none of the
  RBAC/org-scoping code needed to change. If no `User` row matches the email,
  the request is rejected with `403` and a "not provisioned" message rather
  than being treated as unauthenticated — the person proved who they are to
  Clerk, they just haven't been added to Jupiter yet.
- **Frontend** — `<ClerkProvider>` wraps the app (`frontend/src/main.tsx`);
  `/login` renders Clerk's own `<SignIn>` component (handles password, MFA
  enrollment/challenge, session refresh — all in Clerk's UI, not ours).
  `lib/auth.tsx`'s `useAuth()` wraps Clerk's hooks and fetches `/auth/me`
  once signed in, exposing `{ user, loading, notProvisioned, logout }` so the
  rest of the app didn't need to change how it reads the current user.
  `lib/api.ts` pulls a fresh Clerk token (`getToken()`) on every request
  rather than caching one, since Clerk tokens are short-lived and auto-refresh.
- **Provisioning a user**: `npm run seed` for the very first admin (before
  anyone can sign in to use the app at all); every admin after that via
  `POST /users` (or the Team page) — see "Access control" below, which
  creates the `User` row and sends a real Clerk invitation in one step.
  Sign-up is invite-only instance-wide, not "anyone can register and the
  email happens to match."
- MFA, password policy, session lifetime, etc. are all configured in the
  Clerk dashboard, not in this codebase.

## Remediation roadmap

`GET /engagements/:id/roadmap` returns every still-open finding
(OPEN/REMEDIATING) bucketed by severity × effort:

- **quick_win** — high business value (severity CRITICAL/HIGH/MEDIUM), low
  effort (`QUICK_WIN`/`SMALL`) — do these first
- **long_term** — effort `LARGE`, regardless of severity
- **plan** — everything else with an effort set
- **uncategorized** — effort not yet estimated

Bucketing logic lives once, server-side, in `findings.routes.ts` — not
re-derived in the frontend. Effort is set via `PATCH /findings/:id`
(`remediationEffort`), from either the Roadmap tab or the finding detail panel.

## Compliance control library

`POST /engagements/:id/compliance-checks/seed` (`{ framework }`) loads a
standard control set as `PENDING` checks instead of a consultant typing each
one in by hand — idempotent per engagement+framework+control, safe to click
again. Two libraries are built in (`src/modules/compliance/control-library.ts`):

- **ISO27001** — the full ISO/IEC 27001:2022 Annex A, all 93 controls across
  the four themes (organizational/people/physical/technological)
- **NDPR** — a 20-item checklist derived from the Nigeria Data Protection Act
  2023 / NDPR's core obligations (lawful basis, DPO, DPIA, breach
  notification timelines, data subject rights, etc.) — there's no official
  numbered control catalog for NDPA/NDPR the way there is for ISO 27001, so
  this is a practical checklist, not a verbatim reproduction of statutory text

The Compliance tab has a "gaps only" filter (FAIL/PARTIAL) once controls are
assessed, and status is editable inline per control (`PATCH
/compliance-checks/:id`).

## Staff training

`TrainingSession` rows (topic, scheduled date, status, attendee count,
encrypted notes) scoped to an engagement — `POST`/`GET
/engagements/:id/training-sessions`, `PATCH /training-sessions/:id`. Built-in
topics match the brief: phishing, password hygiene, handling sensitive data,
common app/infra mistakes, plus a custom-topic option.

## Manual testing

Automated scanning (below) only covers `WEB`/`API` assets and non-intrusive
checks — deeper testing (auth'd flows, business-logic issues, anything on a
`SERVER`/`NETWORK`/`CLOUD`/`MOBILE` asset) is still a human doing the work.
The Assets tab's "Start manual test" action (`AssetsTab.tsx`) exists so that
work has one place to happen instead of two: it creates a `Test` for that
asset (`POST /engagements/:id/tests`), immediately flips it to
`IN_PROGRESS`, and opens a findings-logging form scoped to that
test/asset — no re-selecting either one for every finding. Findings appear
in a running list as they're logged (`GET
/engagements/:id/findings?testId=`) and "Mark test complete" closes it out.
Resuming later re-opens the same panel against the still-`IN_PROGRESS` test
rather than starting a new one.

No backend changes were needed for this — `POST /tests`, `PATCH
/tests/:id`, and `POST .../findings` already existed and already enforce
the same authorization gate as everything else; this is entirely a frontend
workflow built on top of them. Verified live end to end: started a test,
progressed it to `IN_PROGRESS`, logged a finding against it, confirmed it
came back correctly scoped by `testId`, and marked the test `COMPLETE`.

## Vulnerability scan import

`POST /engagements/:id/tests/:testId/findings/import` bulk-creates findings
from scanner output instead of typing each one in by hand
(`src/modules/findings/scan-import.ts`):

- `format: "nuclei"` — understands [Nuclei](https://nuclei.projectdiscovery.io/)'s
  JSONL result shape (free/open-source, a common choice for authorized
  automated scanning)
- `format: "normalized"` — a documented item schema (`title`, `description`,
  `severity`, `cvssScore?`, `assetId?`/`assetIdentifier?`) for any other
  tool's output converted upstream

Either way, the target asset is matched by **decrypting** each engagement
asset's identifier and comparing against the scan result's target —
identifiers are encrypted at rest, so this can't be a SQL `WHERE` clause.
Items that can't be matched to an in-scope asset are skipped with a reason
in the response, not silently dropped. Verified live against both formats,
including the skip-with-reason path for an unmatched target.

This import endpoint itself never runs a scanner — it's the "then import the
results" half of the workflow, and stays usable from Vercel's serverless
runtime either way. **Website scanning** (below) is what actually runs one.

## Presigned evidence uploads

The evidence-upload route (`POST /findings/:id/evidence`) sends the file
through this server's own request body — fine for local dev, but Vercel's
default body-size limit (4.5MB) rejects anything bigger, and evidence
(screen recordings, pcaps) routinely isn't small. `frontend/src/lib/
evidenceUpload.ts` adds a second path that bypasses this server for the
actual file bytes entirely:

1. `POST .../evidence/presign` — server generates a fresh DEK (via
   `kms.generateDataKey()`) and a short-lived, single-use Supabase signed
   upload URL/token, returns both to the browser.
2. **The browser encrypts client-side** with WebCrypto (`AES-GCM`, 12-byte
   IV, AAD-bound) — the exact same wire format `src/crypto/envelope.ts`
   produces server-side, so either side can decrypt what the other
   encrypted — then PUTs the ciphertext straight to Supabase Storage using
   that URL/token. This server never sees the plaintext *or* the ciphertext
   in transit.
3. `POST .../evidence/complete` — a small JSON call (regardless of file
   size) recording the `Evidence` row from what the browser reports. The
   server confirms the object actually landed in storage
   (`ObjectStorage.exists`) before trusting the client-supplied metadata,
   rather than taking it on faith.

The SHA-256 used for the malware check (see below) is computed client-side
too (`crypto.subtle.digest`), since the server never has the plaintext to
hash itself.

This only works when the configured `ObjectStorage` provider implements the
optional `createUploadUrl`/`exists` methods — Supabase does
(`src/crypto/providers/supabase-storage.ts`); local-disk dev storage
doesn't (no meaningful "presigned URL" for your own filesystem, and no
size-limit problem to solve there anyway). `uploadEvidenceDirect()` returns
`false` when unsupported, and `FindingDetail.tsx` transparently falls back
to the original multipart route — one upload button, two paths, caller
doesn't need to know which ran.

Requires `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` in the
frontend env — the modern `sb_publishable_...` key, **not** the backend's
secret `service_role` key. It's safe to expose client-side by design: every
table and bucket has RLS enabled with zero policies, so the publishable key
can't read or write anything through the normal API on its own. The
one narrow thing it *can* do is complete an upload against a URL this
server already signed for one specific object — Storage validates that
signed token directly, independent of RLS.

Verified live end to end, not just code-complete: a real presigned URL was
issued against the actual Supabase project, a file was encrypted with
WebCrypto and uploaded directly to Storage (bypassing the backend
entirely), and downloading it back through the normal decrypt path returned
byte-identical plaintext — proving the browser-produced ciphertext format
is fully interoperable with the server's own AES-256-GCM implementation.

## Website scanning

Lets an operator trigger a real scan against a client's own site or API
directly from the app, instead of running Nuclei by hand and uploading the
JSONL separately. Two things have to be true before that's allowed:

1. **The engagement has a signed authorization on file** (same
   `authorizationSignedAt` gate as everything else — see "Security notes").
2. **The specific asset has proven ownership.** Typing a URL into a form
   isn't proof anyone controls it — without this, "scan this URL" is an open
   SSRF/abuse primitive against any site on the internet, authorized or not.
   `src/modules/assets/verification.ts` implements two real, live checks
   plus a documented manual override:
   - `POST .../assets/:id/verification/start` (`{ method: "DNS_TXT" |
     "HTTP_FILE" }`) generates a random token and returns exactly what to
     publish (a DNS TXT record, or a file at
     `/.well-known/jupiter-verification.txt`).
   - `POST .../assets/:id/verification/check` does the actual lookup
     (`dns.resolveTxt` / a capped, timeout-bound `fetch`) and flips the
     asset to `VERIFIED` only on an exact match.
   - `POST .../assets/:id/verification/manual` (`{ justification }`) lets a
     `security_admin` attest ownership out of band — e.g. infra already
     covered by the signed ROE/SOW — logged to the audit trail with the
     justification recorded, not silently trusted.

Once an asset is `VERIFIED`, `POST /engagements/:id/assets/:assetId/scan`
(`src/modules/scanning`) creates a `Test` + `ScanJob` row and spawns
[Nuclei](https://nuclei.projectdiscovery.io/) against it in the background,
returning `202` immediately — the frontend polls `GET /scan-jobs/:id` (or
`GET /engagements/:id/scan-jobs` for the list) rather than blocking on the
HTTP request. Whatever Nuclei finds lands as ordinary `Finding` rows through
the exact same dedup-aware importer the manual upload path uses
(`src/modules/findings/import.service.ts`) — a `ScanJob` also keeps the full
raw JSONL output encrypted (`rawResultEnc`) for audit purposes, visible only
to `security_admin` (same sensitivity tier as evidence).

Safety constraints, all enforced server-side, not just documented:

- **Non-intrusive by default.** The template set is fixed to
  `cors,exposure,misconfig,tech,generic,headers` — configuration/header
  checks, not fuzzing, brute-force, or exploit templates. Anything more
  aggressive is a manual pentest activity (`POST .../findings` by hand), not
  something triggerable unattended from the dashboard.
- **Rate-limited and time-boxed.** 60 requests/sec against the one target,
  hard-killed after 5 minutes (`MAX_RUNTIME_MS`) — this tag set clusters
  down to several thousand requests, so a full run against one host takes a
  couple of minutes, not seconds; verified live end to end. `-duc` disables
  Nuclei's own update-check network call so a scan's latency doesn't depend
  on GitHub being reachable.
- **SSRF guard.** Before spawning anything, the target hostname is resolved
  and rejected if it points at a private/loopback/link-local address
  (`isPrivateAddress` in `scan-runner.ts`) — otherwise a bad or malicious
  asset URL could turn this feature into a probe of the server's own
  network. `ALLOW_INTERNAL_SCAN_TARGETS=true` lifts this for local dev/demo
  use against your own machine only.
- **One scan at a time per asset**, enforced by checking for an existing
  `QUEUED`/`RUNNING` `ScanJob` before starting another.
- **Self-healing on restart.** There's no separate job queue — this same
  process runs the scan, so if it restarts mid-scan that job would
  otherwise stay `RUNNING` forever and permanently block re-scanning that
  asset. `failOrphanedScanJobs()` (`src/server.ts`) sweeps any
  `QUEUED`/`RUNNING` job to `FAILED` at boot.

**Deployment note:** this endpoint needs the Nuclei binary and a
long-running process (`NUCLEI_BIN_PATH`, defaults to expecting `nuclei` on
PATH), so — unlike scheduled key rotation, which is ordinary fast in-process
crypto work and runs fine on Vercel Cron — it is **not usable on Vercel's
serverless runtime** (no persistent binary, no process that outlives one
request). Run it on a normal host/container/VM if you want this feature live;
the rest of the app — including the manual JSONL import path above — has no
such requirement.

Verified live end to end: a `WEB` asset was proven via a real HTTP_FILE
check (token published to a live server, fetched and matched over the
network, not mocked), and a separate asset's full scan pipeline — trigger,
spawn, `ScanJob` status transitions, dedup-aware import, completion — was
run against a real target with real Nuclei output.

## Attack surface discovery

Jupiter's first addition beyond Enforcer's original scope: finding assets a
client didn't know to declare, not just scanning the ones they did. Same
non-intrusive, human-gated posture as "Website scanning" above, extended one
step earlier in the pipeline.

`POST /engagements/:id/assets/:assetId/discover` (`src/modules/discovery`)
only runs against an asset that's already `VERIFIED` — the exact same
ownership gate scanning uses, for the same reason: querying certificate-
transparency logs and probing whatever resolves is still directed at a
target, so proving control of the root domain first is what keeps this from
being an open abuse primitive against any domain on the internet. It also
requires the engagement's signed authorization and an in-scope `WEB`/`API`
asset, same as scanning.

What a discovery run actually does, in order:

1. **Certificate-transparency lookup.** Queries `crt.sh` for every
   certificate ever issued for `*.<root-domain>` — a purely passive OSINT
   step; no request ever reaches the target itself. This is how it finds
   subdomains nobody remembered to declare (forgotten staging environments,
   old marketing microsites, etc.).
2. **Liveness check.** A plain DNS lookup on each candidate — anything that
   no longer resolves is dropped, not reported, so the review queue reflects
   today's attack surface, not certificate history.
3. **Port check.** For whatever's live and resolves publicly, a connect-only
   TCP check (no banner grab) against eight well-known ports
   (21/22/25/80/443/3389/8080/8443) — never anything resembling a full port
   sweep. A host that resolves to a private/internal address is recorded
   with no ports checked at all, same `isPrivateAddress` guard scanning uses.

Results land as `DiscoveredAsset` rows, **never** directly as scannable
`Asset`s — a human reviews the queue (`GET .../discovered-assets`) and
either:

- `POST /discovered-assets/:id/promote` — creates a real `Asset`, but it
  starts `UNVERIFIED`. Promotion only ever expands what's *tracked*; the new
  asset still has to pass the same DNS/HTTP ownership verification as
  anything manually added before it's ever scannable. Discovering a
  subdomain is not proof of controlling it.
- `POST /discovered-assets/:id/ignore` — dismisses it, logged like every
  other reviewed action.

Safety constraints, all enforced server-side:

- **Passive-first.** The only step that touches a discovered host at all is
  a connect-only port check — no banner reads, no HTTP requests, no
  brute-forcing of hostnames.
- **Time- and volume-boxed.** Capped at 50 CT-log candidates per run
  (`MAX_CANDIDATES`) and a 3-minute runtime ceiling — leftover candidates
  are picked up on the next run rather than the job running unbounded.
- **One run at a time per asset**, and **dedup against prior runs** — a
  re-run doesn't re-surface the same subdomain as a fresh row every time
  (ciphertext can't be uniqued at the DB level, so this decrypts and
  compares in application code, same approach `import.service.ts` uses for
  finding dedup).
- **Self-healing on restart**, same as scanning — `failOrphanedDiscoveryJobs()`
  (`src/server.ts`) sweeps any stuck `QUEUED`/`RUNNING` job to `FAILED` at boot.

**Deployment note:** same constraint as scanning — this needs a
long-running process (DNS lookups and TCP connects don't complete inside a
single serverless invocation reliably), so it's **not usable on Vercel's
serverless runtime** on its own. Run it wherever "Website scanning" runs.

## AI-assisted triage

Jupiter's second addition beyond Enforcer's original scope: an optional
AI-assisted first pass on every finding, drafting remediation guidance and
flagging a false-positive likelihood — for a human to review, edit, or
discard, never applied automatically. Same "speeds up the human-in-the-loop
step without removing it" philosophy as the active-response containment
action (`POST .../findings/:id/response-actions/contain`), which is also
always human-triggered.

`src/ai` follows the exact same swappable-provider shape as
`src/threat-response` and `src/esignature`: `AiTriageProvider` is the
interface, `NoopAiTriageProvider` (default) drafts nothing, and
`AnthropicAiTriageProvider` (`AI_TRIAGE_PROVIDER=anthropic`) calls the
[Claude Messages API](https://docs.anthropic.com/) directly via `fetch` —
no SDK dependency, same convention `src/esignature/providers/documenso.ts`
uses for its own external calls.

**The draft is structurally separate from real data, not just a UI
convention.** A `Finding` has `aiRemediationDraftEnc` /
`aiFalsePositiveLikelihood` / `aiTriageRationaleEnc` / `aiTriagedAt` —
distinct columns from `remediationGuidanceEnc` and `status`, which only a
human ever writes to. There is no code path where a model's output lands
directly in the fields a report or roadmap reads from:

- A draft is requested either automatically (fire-and-forget, on every
  finding creation — manual and scan-import both) or on demand
  (`POST /findings/:id/triage`, `security_admin`, useful for findings
  created before this feature existed or after an edit). Both paths only
  ever write the `ai*` columns.
- `GET /findings/:id` returns the draft alongside the real
  `remediationGuidance` field, clearly separated in the response — a client
  can't accidentally render one as the other.
- Promoting a draft into real guidance is one explicit action:
  `PATCH /findings/:id { "acceptAiRemediationDraft": true }` copies the
  current draft into `remediationGuidanceEnc`. 400s if no draft exists yet.
  There's no bulk-accept and no auto-accept-on-creation — every promotion is
  a deliberate, audit-logged human decision.
- `rationale` (why the model called the false-positive likelihood what it
  did) is always stored and always returned alongside the draft — never a
  bare confidence number with no justification a reviewer can check.

**Failure mode is silence, not a broken finding.** If `AI_TRIAGE_PROVIDER`
is unset, if the Anthropic API errors, times out, or returns something that
doesn't parse as the expected JSON shape, `draftTriage()` returns `null` and
the finding is simply left undrafted — `POST /findings/:id/triage` reports
`{ drafted: false }` rather than a 500, and the fire-and-forget path on
creation logs a warning and moves on. A finding never ends up in a partial
or corrupted state because a model call had a bad day.

## Scheduled scanning

`GET /internal/scheduled-scans` sweeps every verified `WEB`/`API` asset on
an authorized, `ACTIVE` engagement and starts a scan for any that don't
already have one in flight (capped at `MAX_SCANS_PER_RUN` — 5 — per
invocation, so one run can't kick off a pile of concurrent Nuclei processes;
anything past the cap just gets picked up on the next run). It shares the
exact same `startScan()` helper the manual "Run scan" button uses
(`scan-runner.ts`), so a scheduled scan behaves identically to a
manually-triggered one in every way — same safety limits, same dedup, same
findings pipeline.

**This never generates or sends anything to the client.** It only starts
scans; results land as ordinary `Finding` rows for a `security_admin` to
review in the dashboard, exactly like a manual scan does. Report generation
stays a separate, explicit, human-triggered action (`POST
/engagements/:id/reports/generate`) — "scans run automatically" and "a
human reviews before the client sees anything" are two different gates, and
this only ever touches the first one.

Protected the same way as `/internal/rotate-keys` (`CRON_SECRET` via
`Authorization: Bearer`, refuses every request if unset) — but **it is not
wired into `vercel.json`'s `crons` array**, deliberately: this needs the
same Nuclei-plus-persistent-process setup as manual scanning, so a Vercel
Cron entry would just fail/timeout the same way the manual trigger would.
Point whatever scheduler actually runs on the same host as the backend at
it instead — a plain crontab entry works fine:

```cron
0 2 * * *  curl -s -X GET https://your-backend-host/internal/scheduled-scans \
             -H "Authorization: Bearer $CRON_SECRET"
```

Verified live end to end against real data: correctly matched the two
verified assets from earlier testing, started real scans for both, and a
second immediate call correctly skipped both with "already has a scan in
progress" rather than double-starting them.

## Notifications

A `CRITICAL`/`HIGH` finding from *any* creation path — manual entry, bulk
JSONL import, an automated or scheduled scan — triggers `notifyIfSevere()`
(`src/notifications`), fire-and-forget so it never adds latency to the
request that created the finding (verified live: response time was
unaffected with zero notifiers configured, since the no-op check happens
before any async work at all).

Fan-out, not a single swappable provider like `KmsProvider` — you might
reasonably want Slack *and* email, so any combination of the following is
valid, including neither (the default):

- **Slack** (`SLACK_WEBHOOK_URL`) — a plain incoming-webhook POST. Simple
  and stable enough that this reads as more confidently correct than the
  Documenso/CrowdStrike integrations, even though it's equally unverified
  against a real webhook — no credentials available.
- **Email** (`RESEND_API_KEY` + `NOTIFICATION_EMAIL_FROM` +
  `NOTIFICATION_EMAIL_TO`) — via [Resend](https://resend.com). **Verified
  live**: a real email sent successfully through the actual API (message
  ID returned, HTTP 200), both as a direct API check and through the app's
  own finding-creation code path.

One failing notifier doesn't block another (`Promise.allSettled`) — a
misconfigured Slack webhook shouldn't also silently kill email delivery.

## Malware detection & active response

Two related but separate features, both entirely optional and both off by
default:

**Detection** (`src/integrations/virustotal.ts`, `malware-check.ts`) — set
`VIRUSTOTAL_API_KEY` to enable:

- **Evidence file hashing.** Every uploaded evidence file is SHA-256 hashed
  (`src/modules/evidence/evidence.routes.ts`) before encryption — the hash
  itself isn't sensitive and lets a reputation check run without ever
  sending the file itself to a third party. A fire-and-forget check
  (`checkEvidenceMalware`) then looks the hash up against VirusTotal and
  sets `Evidence.malwareStatus` to `CLEAN`, `FLAGGED`, or `UNAVAILABLE` —
  deliberately three states, not two: VT returning "never seen this hash"
  is **not** the same as "confirmed clean," and the badge in the frontend
  (`FindingDetail.tsx`) reflects that (an unavailable verdict shows nothing
  rather than a false-looking green checkmark).
- **Domain/URL reputation.** At the end of a website scan
  (`scan-runner.ts`), the target URL is checked against VirusTotal's URL
  reputation. A flagged result becomes an ordinary `Finding` — same
  dedup-aware import path as everything else — with concrete containment
  steps in `remediationGuidance` (verify it's not a false positive, isolate
  the host, preserve evidence, rotate credentials, block at the perimeter).

**Active response** (`src/threat-response/`) — a `ThreatResponseProvider`
interface, same swappable-boundary pattern as `KmsProvider`
(`src/crypto/kms.ts`), deliberately narrow: **one** action, network
containment of a host, because that's the EDR primitive that's both widely
API-supported and reversible if it fires on a false positive. This app never
deletes files, kills processes, or blocks traffic directly — it asks a
system that already has scoped, consented authority over the target (an EDR
agent already installed there) to do that instead.

- `NoopThreatResponseProvider` (default) takes no action and says so.
- `CrowdStrikeThreatResponseProvider` (`THREAT_RESPONSE_PROVIDER=crowdstrike`,
  `CROWDSTRIKE_CLIENT_ID`/`CROWDSTRIKE_CLIENT_SECRET`) calls the real Falcon
  API (OAuth2 token → resolve hostname to a device → request containment).
  **Untested against a live CrowdStrike account** — no credentials available
  to verify it end to end, same caveat as `AwsKmsProvider`; it's ordinary
  Falcon API usage against documented endpoints, but confirm it yourself
  before relying on it.
- `POST /findings/:id/response-actions/contain` is the only way to trigger
  this — **always a human clicking a button** (`FindingDetail.tsx`'s
  "Attempt containment"), never automatic. It resolves the containment
  target from the finding's own asset, not from the request body, so it
  can't be used to ask the provider to contain an arbitrary, unrelated host.
  Audit-logged either way (`finding.responseAction.contain`).

Verified live: with no `VIRUSTOTAL_API_KEY` set, an uploaded evidence file
correctly resolved to `UNAVAILABLE` (not a false "clean"); with no
`THREAT_RESPONSE_PROVIDER` set, the containment endpoint correctly resolved
the target host from a real finding's asset and returned the Noop provider's
"nothing was done" response. The VirusTotal *positive* path (an actually
flagged hash/URL) and the CrowdStrike provider are code-complete but not
verified against live accounts — no credentials available in this
environment.

## Audit logging

`src/modules/audit/audit.service.ts#writeAuditLog` is called on every
view/create/update/download/decrypt of a sensitive resource, and on every
RBAC denial, before the response is returned. `AuditLog` is append-only by
convention — no route calls update/delete on it. Query via
`GET /audit-logs` (security_admin only).

## Authorization gate

No `Test` (and therefore no `Finding`) can be created until an `Engagement`
has been explicitly authorized. This is enforced in `tests.routes.ts` (and
`scan.routes.ts`), not just in process — never test without written
authorization. There are two ways to clear the gate:

- **Manual** (`POST /engagements/:id/authorize`) — a `security_admin`
  self-attests that a signed ROE/scope document exists outside the system,
  supplying who signed it and a reference. Always available, no external
  dependency, but it's exactly as trustworthy as the person clicking the
  button — the system has no way to verify the document was actually
  signed by anyone.
- **E-signature** (`src/esignature/`) — sends the actual ROE PDF out
  through a real e-signature provider (`POST
  /engagements/:id/authorize/send`) and only opens the gate once that
  provider itself confirms it's signed (`POST
  /engagements/:id/authorize/check`), not on anyone's say-so. Same
  swappable-provider pattern as `KmsProvider`/`ThreatResponseProvider`:
  `NoopESignatureProvider` (default) errors clearly rather than pretending
  to send anything; `DocumensoESignatureProvider`
  (`ESIGNATURE_PROVIDER=documenso`) calls a real provider — **live-debugged
  against a real account**, not just written from docs: three real bugs in
  the request shape (a required `payload.type` field, a signature field
  having to actually be placed on the document before it can be
  distributed, and `positionX`/`positionY` field naming) were found and
  fixed from Documenso's own error responses. A full create-and-distribute
  round trip with all three fixes together hasn't completed cleanly yet —
  the account hit Documenso's envelope-creation rate limit partway through
  verification (a real 429, reads as a tighter quota than their general
  per-second limit). Documenso's v2 API is itself still documented as
  beta. Exact state — what's confirmed vs. still pending a clean end-to-end
  run — is called out directly in `providers/documenso.ts`.

Once `authorize/check` confirms SIGNED, it also calls
`getSignedDocument()` and — if the provider returns one — encrypts and
stores the **actual signed PDF**, not just proof-it-happened metadata
(`GET /engagements/:id/authorization-document` to retrieve it, same
encrypted-at-rest pattern as evidence/reports, open to every org role
since it's the client's own signed contract). This never blocks
confirming the authorization itself if the fetch fails — the verified
signature (`authorizationEnvelopeId` + provider-confirmed
`authorizationSignedAt`) is what actually gates testing; the stored PDF is
additive. Live-verified as far as honestly possible without a real
Documenso account: the download route correctly 404s with a clear message
for engagements with no stored document (the manual-authorization case).

Verified live end to end for what doesn't require a real account: sent a
request through the Noop provider and got a clear, correctly-worded
"not configured" error (502) rather than a silent failure; confirmed
`authorize/check` without a prior `send` returns a clean 400; confirmed the
pre-existing manual `/authorize` path is completely unaffected by any of
this (regression-checked after adding `authorizationMethod` to it).

## API surface

See route files under `src/modules/*/`. Summary:

List endpoints are deliberately undecrypted/metadata-only (no `*Enc` field is
touched, so browsing a list never triggers a decrypt or a sensitive-field
audit entry) — only the single-resource `GET`s below decrypt and audit-log.

```
GET    /auth/me                              (resolves the signed-in Clerk user to their role/orgId)
GET    /users                                (security_admin; the current team)
POST   /users                                (security_admin; creates the User row + sends a real Clerk invitation)
DELETE /users/:id                            (security_admin; revokes access immediately, not the Clerk account itself)
GET    /security/status                      (security_admin; live posture read for the /security page)
POST   /clients                              (security_admin)
GET    /clients                              (security_admin: all; client roles: own org only)
GET    /clients/:id
GET    /clients/:id/findings-history         (aggregated across every engagement for the client)
PATCH  /clients/:id/kms-key                  (security_admin; assigns a dedicated per-tenant key — see "Per-tenant encryption keys")
POST   /engagements                          (security_admin)
GET    /engagements                          (?clientId= optional filter)
GET    /engagements/:id
PATCH  /engagements/:id/scope                (security_admin)
POST   /engagements/:id/authorize            (security_admin; manual self-attestation)
POST   /engagements/:id/authorize/send       (security_admin; e-signature, multipart PDF; 502 if no provider)
POST   /engagements/:id/authorize/check      (security_admin; polls provider, opens the gate once SIGNED)
GET    /engagements/:id/authorization-document (the actual signed PDF, if the e-signature path fetched one)
POST   /engagements/:id/assets               (security_admin)
GET    /engagements/:id/assets
POST   /engagements/:id/assets/:id/verification/start   (security_admin; { method: "DNS_TXT" | "HTTP_FILE" })
POST   /engagements/:id/assets/:id/verification/check   (security_admin; live DNS/HTTP check)
POST   /engagements/:id/assets/:id/verification/manual  (security_admin; { justification })
POST   /engagements/:id/assets/:id/scan      (security_admin; requires VERIFIED + authorization; 202, async)
GET    /engagements/:id/scan-jobs
GET    /scan-jobs/:id                        (rawResult only for security_admin)
POST   /engagements/:id/assets/:id/discover  (security_admin; requires VERIFIED + authorization; 202, async — see "Attack surface discovery")
GET    /engagements/:id/discovery-jobs
GET    /engagements/:id/discovered-assets    (decrypted; the review queue)
POST   /discovered-assets/:id/promote        (security_admin; NEW only; creates an UNVERIFIED Asset)
POST   /discovered-assets/:id/ignore         (security_admin; NEW only)
POST   /engagements/:id/tests                (security_admin; requires authorization)
GET    /engagements/:id/tests
PATCH  /engagements/:id/tests/:testId        (security_admin)
POST   /engagements/:id/tests/:testId/findings (security_admin)
POST   /engagements/:id/tests/:testId/findings/import (security_admin; bulk, nuclei/normalized)
GET    /engagements/:id/findings             (?testId= optional filter)
GET    /engagements/:id/roadmap              (bucketed: quick_win/long_term/plan/uncategorized)
GET    /findings/:id
PATCH  /findings/:id                         (security_admin; status and/or remediationEffort and/or acceptAiRemediationDraft)
POST   /findings/:id/triage                  (security_admin; on-demand AI draft — see "AI-assisted triage")
POST   /findings/:id/evidence                (security_admin, multipart — small files / local storage backend)
POST   /findings/:id/evidence/presign        (security_admin; 501 if storage backend doesn't support it)
POST   /findings/:id/evidence/complete       (security_admin; records the row after a direct upload)
GET    /findings/:id/evidence                (not exec_client)
GET    /findings/:id/evidence/:evidenceId    (not exec_client)
POST   /engagements/:id/compliance-checks    (security_admin)
POST   /engagements/:id/compliance-checks/seed (security_admin; { framework: "ISO27001" | "NDPR" })
GET    /engagements/:id/compliance-checks
PATCH  /compliance-checks/:id                (security_admin)
GET    /engagements/:id/compliance-summary
POST   /engagements/:id/training-sessions    (security_admin)
GET    /engagements/:id/training-sessions
GET    /training-sessions/:id
PATCH  /training-sessions/:id                (security_admin)
POST   /engagements/:id/reports/generate     (security_admin)
GET    /engagements/:id/reports              (exec_client sees EXECUTIVE only)
GET    /reports/:id/download                 (exec_client limited to EXECUTIVE type)
POST   /findings/:id/retest                  (security_admin)
GET    /findings/:id/retest-history
POST   /findings/:id/response-actions/contain (security_admin; Noop unless THREAT_RESPONSE_PROVIDER set)
GET    /audit-logs                           (security_admin)
GET    /internal/rotate-keys                 (CRON_SECRET via Authorization: Bearer; not a user-facing route)
GET    /internal/scheduled-scans             (CRON_SECRET; not wired to vercel.json — needs a persistent host, see "Scheduled scanning")
```

## Supabase project

This app's Postgres and file storage run on Supabase project **demi**
(`rwrkimrznijzxcuaudbd`, `eu-west-2`), reused from an existing paused project
rather than a new one because the account is capped at 2 active free
projects. To make room, **adele** (`bqvwivbyuzmiujwcqnvs`) was paused — its
data is untouched and it can be resumed anytime from the Supabase dashboard.

- All 12 tables have RLS enabled with **no policies** (deny-by-default). This
  blocks Supabase's `anon`/`authenticated` REST API roles entirely; it does
  not affect this app, which connects directly via `DATABASE_URL` (a role
  that bypasses RLS), never through PostgREST.
- Evidence/report ciphertext lives in the private `jupiter-evidence` bucket,
  accessed only via `SUPABASE_SERVICE_ROLE_KEY` from the server.
- If you ever add a browser/mobile client that talks to Supabase directly
  (not through this API), you'll need real RLS policies scoped to `orgId`
  before using the `anon` key — the current lockdown assumes only this
  backend ever touches these tables.

## Deploying to Vercel

This is a monorepo (backend at repo root, frontend in `frontend/`) — deploy
it as **two separate Vercel projects** against the same GitHub repo.

**Backend project** — root directory left at `/`, framework preset "Other":

- `api/index.ts` exports the Express app for Vercel's Node runtime; a root
  `vercel.json` rewrites every path to it, since the app's own routes aren't
  prefixed with `/api` (e.g. `/auth/me`, `/clients`).
- A `postinstall` script runs `prisma generate` — Prisma's query-engine
  binary is platform-specific, so it must be regenerated during Vercel's own
  (Linux) build rather than reusing whatever was generated on a dev machine.
- Environment variables to set (same names/values as `.env`): `DATABASE_URL`,
  `CLERK_SECRET_KEY`, `CLERK_PUBLISHABLE_KEY`, `STORAGE_BACKEND`, `SUPABASE_URL`,
  `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_STORAGE_BUCKET`, `CMK_BASE64`,
  `CMK_ID`, `CMK_VERSION` — plus **`CORS_ORIGINS`**, set to the frontend
  project's URL once it exists (comma-separated if there's more than one).
  Without it the API defaults to allowing any origin, which is fine for
  local dev but should not ship as the permanent state for a real deployment.
- **`CRON_SECRET`** — set this to enable scheduled key rotation (Vercel
  automatically sends it as `Authorization: Bearer $CRON_SECRET` to the cron
  target in `vercel.json`). Leave it unset to disable the feature outright —
  the route refuses every request rather than defaulting open.
- To use real AWS KMS instead of the local dev stand-in: `KMS_PROVIDER=aws`,
  `AWS_REGION`, `AWS_KMS_KEY_ID` (see "How the encryption works" above).
- Known constraint: Vercel's default request body limit (4.5MB on the free
  tier) is smaller than the app's 50MB evidence-upload limit — large evidence
  files will be rejected until that's addressed (e.g. presigned direct-to-Storage
  uploads), not a blocker for small demo files.
- **Website scanning (`POST .../assets/:id/scan`) will not work here** — it
  spawns a real Nuclei process and needs a binary + a process that outlives
  one request, neither of which exist on Vercel's serverless runtime. The
  rest of the app, including manually uploading scan results via `POST
  .../findings/import`, is unaffected. Run the backend on a normal
  host/container instead if you need in-app scanning live.

**Frontend project** — root directory set to `frontend` (Vercel auto-detects
Vite from there). Environment variables: `VITE_API_URL` = the backend
project's URL (no trailing slash) — there's no dev proxy in a static
production build, so the frontend needs to know exactly where the API lives —
`VITE_CLERK_PUBLISHABLE_KEY` (same publishable key as the backend's
`CLERK_PUBLISHABLE_KEY`), and `VITE_SUPABASE_URL` +
`VITE_SUPABASE_PUBLISHABLE_KEY` (see "Presigned evidence uploads" — the
modern `sb_publishable_...` key, safe client-side, never the secret
`service_role` key).

**First deployment: bootstrapping the first admin.** `POST /users` — the
normal way to grant access — requires an existing `SECURITY_ADMIN` to call
it, and a brand-new database has none. Right after the first
`prisma migrate deploy` against a fresh environment, run:

```
npx ts-node --transpile-only scripts/bootstrap-admin.ts "Full Name" admin@example.com
```

This creates that one `User` row and sends a real Clerk invitation, exactly
like `POST /users` does — the only difference is it doesn't require an admin
to already exist to call it. It refuses to run (rather than silently
succeeding) if this deployment already has any `SECURITY_ADMIN` at all, so
it can't become an ad-hoc admin-creation backdoor after initial setup —
every subsequent user, including additional admins, goes through the normal
Team page / `POST /users` from then on.

## Deferred to v2

- Broader/deeper automated scanning (auth'd crawling, active/intrusive
  templates, other scanners like Nessus/OpenVAS/Burp) — "Website scanning"
  above covers non-intrusive Nuclei checks triggered in-app; anything more
  aggressive is still a manual pentest activity by design, not a v2 gap so
  much as a deliberate line between "automated" and "requires a human"
- Real KMS custody is code-complete (`AwsKmsProvider`, `KMS_PROVIDER=aws`) but
  **untested against a live AWS account** — no credentials available to
  verify it end to end; ordinary AWS SDK v3 usage, but confirm it yourself
  before trusting it with real client data
- Same caveat for `CrowdStrikeThreatResponseProvider`
  (`THREAT_RESPONSE_PROVIDER=crowdstrike`) and the Slack notification
  provider — code-complete, untested against live accounts, no credentials
  available. The VirusTotal integration's "flagged" path is similarly
  unverified against a real positive result (only the "unconfigured/no
  verdict" fallback was tested live).
- `ResendNotificationProvider` **is** verified live — a real email sent
  successfully via the actual API (message ID confirmed).
  `DocumensoESignatureProvider` is **live-debugged, not fully closed out**:
  a real account surfaced three real bugs in the request shape (the
  `payload.type` field, the signature-field placement requirement, and
  `positionX`/`positionY` naming), all fixed from Documenso's own error
  responses rather than guessed — but a full create-and-distribute round
  trip with the corrected shape hasn't completed cleanly yet, because the
  account hit Documenso's envelope-creation rate limit (a real 429, reads
  as a tighter quota than their general per-second limit) partway through
  verification. See `providers/documenso.ts` for the exact state.

## Security notes for anyone deploying this for real

- Generate `CMK_BASE64` and `CRON_SECRET` with a CSPRNG, and get
  `CLERK_SECRET_KEY`/`CLERK_PUBLISHABLE_KEY` from the Clerk dashboard — store
  them all in your platform's secret manager, never commit `.env`.
- Set `KMS_PROVIDER=aws` (or implement an equivalent for your KMS of choice)
  before handling real client data — `LocalKmsProvider` is explicitly
  documented as dev-only, and is still the default.
- Don't run a real engagement without a real, signed authorization document —
  `templates/legal/` has starting-point contracts (MSA, ROE/SOW, NDA, DPA),
  but they need a lawyer's review before use, not just a copy-paste.
- TLS termination is expected in front of this service (load balancer/reverse
  proxy); `helmet()` sets HSTS and other headers app-side as defense in depth.
- Every engagement's authorization must be on file (`authorizationSignedAt`)
  before any test/finding can exist — don't remove that gate.
- Set `CORS_ORIGINS` to the real frontend origin(s) before going live — an
  unset value allows any origin (a deliberate default for local dev, logged
  as a warning on startup so it can't go unnoticed).
- `app.set("trust proxy", 1)` in `app.ts` assumes exactly one reverse proxy
  in front of the app (true for Vercel); it makes `req.ip` reflect the real
  client rather than the proxy, which audit-log IP recording depends on.
- Leave `ALLOW_INTERNAL_SCAN_TARGETS` unset in any real deployment — it
  exists purely so local dev can scan `127.0.0.1`. With it on, "Website
  scanning" (above) will happily scan your own private network if pointed
  at it.

## Backups

Untested restores are a common blind spot — a backup you've never actually
restored isn't a verified backup, it's an assumption. This was tested for
real, not just documented: `pg_dump`/`pg_restore` binaries aren't available
in this dev environment (no Docker daemon either to run a Postgres client
image), so the mechanism was proven at the SQL level instead, against the
real Supabase database — every row of two representative tables (one with
a `jsonb` encrypted-field column, one with an enum column) was read out,
written to disk, then recreated in an isolated `restore_test` schema
(never touching the real tables) and re-inserted, with column types looked
up from `information_schema` and cast explicitly rather than assumed —
enums and encrypted `jsonb` blobs don't round-trip through a naive `INSERT`
without that. Row counts and content matched exactly, encrypted fields came
back byte-for-byte as opaque blobs (no special handling needed — they're
just data as far as Postgres/backup tooling is concerned), and the scratch
schema was dropped afterward.

What this proves: the *data* survives a dump-and-restore cycle correctly,
including the encrypted columns and every enum type in the schema. What it
doesn't replace: an actual `pg_dump`/`pg_restore` (or your platform's
managed backup feature — Supabase's paid tiers include point-in-time
recovery) run against a real environment with those tools installed. Do
that before trusting backups with real client data; this is the one
verification that couldn't be fully completed in this environment, unlike
everything else claimed as "verified live" in this document.
