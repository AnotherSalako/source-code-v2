# Enforcer — architecture blueprint

This is the reusable part of Enforcer: the patterns and scaffolding that
exist independent of "cybersecurity assessment platform" as a domain. If
you're building a different system that needs the same shape — real
customer data, encrypted at rest, role-scoped access, an audit trail, and
a defensible security story — this is what to copy and what to swap.

## What stays the same across a rebuild

**Identity vs. authorization, kept separate.** Clerk owns password/MFA/
sessions. The app's own `User` table owns *authorization* — role and which
org a user belongs to — resolved by looking up the Clerk-verified caller's
email against this table (`src/middleware/auth.ts`). A row must exist here
before a Clerk-authenticated person can do anything. This split means
identity is never your problem to get right (the single highest-risk thing
to hand-roll), while access control stays fully in your own code where you
can actually reason about it.

**RBAC + org-scoped isolation, enforced twice.** `requireRole()` gates by
role; `assertOwnOrg()` (`src/middleware/rbac.ts`) gates by whether the
caller's org matches the resource's org, exempting only the internal-staff
role. Every route that returns another party's data calls both. This is
the pattern that made a live, zero-findings IDOR test across 17 route
modules possible — it's checked at the route layer, not hoped for at the
query layer.

**Envelope encryption behind a swappable KMS.** Every sensitive field is
AES-256-GCM encrypted before it reaches the database (`src/crypto/
envelope.ts`), with the data-encryption-key itself wrapped by a `KmsProvider`
interface (`src/crypto/kms.ts`). Two implementations exist:
`LocalKmsProvider` (a static key, dev/self-host use) and `AwsKmsProvider`
(a real KMS key, HSM-backed). The application code never knows which one
is active — swapping providers is a config change, not a rewrite. This is
what let this session move production data from a shared dev key to real
AWS KMS, and separately what makes self-hosting possible without touching
business logic at all.

**Object storage behind the same pattern.** `ObjectStorage`
(`src/crypto/storage.ts`) abstracts file storage the same way — bytes
handed to it are already ciphertext. `LocalObjectStorage` (disk) and
`SupabaseObjectStorage` (managed bucket) both implement `put`, `get`,
`exists`, and `delete`. A real self-hosted rebuild of this system's
infrastructure (Postgres + storage + hosting, keeping only Clerk) took
under a day specifically because this abstraction already existed —
nothing in `src/modules/**` had to change.

**Append-only audit log, separate from the data it describes.**
`writeAuditLog()` (`src/modules/audit/audit.service.ts`) is called on
every read of sensitive data and every state change, logging who, what,
and whether it was allowed — before the response goes out, not after, so
a crash mid-request still leaves a trail. Audit rows are never deleted or
updated by the API layer, including when the resource they reference is —
deleting a User nulls `AuditLog.userId` rather than deleting the row; the
same precedent extended to full org-erasure (see below).

**Self-service, hard data erasure — not a soft-delete flag.**
`src/modules/clients/client-deletion.service.ts` transactionally deletes
an entire org's data graph in FK-dependency order, then best-effort purges
the associated object-storage files, while leaving the audit trail intact.
This exists because "how do we let a customer actually delete their data"
is a real requirement for anything handling other people's data, not an
Enforcer-specific concern — the pattern (collect the graph, delete
children-before-parents in one transaction, purge files after, log the
erasure itself) is the reusable part.

**Two-tier rate limiting.** A generous general limiter on everything, a
much tighter one (`sideEffectLimiter`) on anything that sends a real
email, costs real compute, or is otherwise expensive to abuse
(`src/middleware/rate-limit.ts`).

**Scheduled automation via a shared-secret internal route, not a logged-in
user.** `/internal/*` routes (`src/modules/internal/`) check a bearer
token against `CRON_SECRET` and refuse-closed if it's unset — no
`requireAuth`, because there's no session in a cron context. Registered
both as platform cron (Vercel) and OS crontab (a persistent box), so the
same code path works regardless of hosting model.

**Notification fan-out, not a single provider.** `NotificationProvider`
(`src/notifications/provider.ts`) lets Slack, email, or any future channel
subscribe to the same two events — a severe finding, and a heartbeat that
fires on every scheduled run regardless of outcome. The heartbeat exists
specifically so silence has one meaning ("something's broken"), not two
("broken" or "nothing to report").

**Tests that mock every external dependency, not the database logic.**
`tests/helpers/test-app.ts` fakes Clerk and Prisma with in-memory stores,
but runs real envelope encryption and drives the real Express app via
supertest — so a route wiring a permission check wrong, or a Zod schema
accepting the wrong shape, actually fails, while no test needs real
credentials or network access.

## What to swap for a different system

The domain model is the non-reusable part: `Client → Engagement →
Asset/Test/Finding → Evidence/Retest` is specific to running security
assessments. A different system replaces this graph entirely but keeps
everything above it — the `User`/org-scoping shape, the encryption
boundary, the audit log, the erasure pattern, the notification fan-out.
Concretely: design the new domain's Prisma schema, decide which fields are
sensitive enough to route through `encryptField`/`decryptField`, and wire
new routes through the same `requireAuth` → `requireRole`/`assertOwnOrg` →
`writeAuditLog` sequence every existing route follows.

## Deployment models — both real, different tradeoffs

Two paths have actually been built and proven, not just discussed:

**Managed (Vercel + Supabase Postgres/Storage, AWS only for the persistent
scanning process).** Automatic backups and point-in-time recovery on the
database, automatic HTTPS/CDN/scaling on the frontend, no single box that
can freeze and take everything down at once. More providers, but each one
is someone else's infrastructure to keep alive, not yours. This is the
safer default for something being handed to a paying customer.

**Fully self-hosted (one box: Postgres + Node + Nginx + object storage on
local disk).** No third-party data-plane dependency, full control, a
cleaner story if a buyer specifically wants to own their whole stack. Real
cost: every piece of reliability the managed path gets for free —
backups, monitoring, redundancy — becomes something a human has to set up
and maintain. A same-day build of this path hit a multi-minute full
unresponsive freeze under light setup load with no OOM evidence in the
logs — root cause unconfirmed. Don't treat this path as production-ready
just because it's running; treat it as production-ready once backups,
monitoring, and the freeze are actually understood.

Both paths keep Clerk. Rebuilding authentication by hand is the one piece
of this blueprint not worth ever doing yourself.

## The actual gap in "blueprint" as a business model

Everything above describes patterns that transfer. It does not describe a
repeatable *process* — standing up either deployment model today is
hours of a person (or an agent) running commands by hand: provisioning
cloud resources one API call at a time, hand-editing env files, manually
wiring DNS and certificates. Turning this into something that ships to
buyer #2 without redoing that work means Infrastructure-as-Code (Terraform
or equivalent) for the chosen deployment model, not just the application
code being portable. The application is the reusable part; the *rollout*
isn't, yet.
