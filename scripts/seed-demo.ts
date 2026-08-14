import "dotenv/config";
import crypto from "crypto";
import { clerkClient } from "@clerk/express";
import { prisma } from "../src/db/prisma";
import { kms } from "../src/crypto";
import { encryptField } from "../src/crypto/envelope";
import { tenantKms } from "../src/crypto/tenant";
import { signCredential } from "../src/modules/agents/ca";
import { deleteClientData } from "../src/modules/clients/client-deletion.service";

// Demo/sandbox mode: a realistic-looking client org a prospect or buyer can
// click through — findings, assets, compliance checks, a training session,
// discovery/watch-mode output, an endpoint agent — without ever touching
// real client infrastructure or a real AWS account. Everything here goes
// through the exact same encryption/data-model path real data does (real
// KMS envelope encryption via the configured provider, a real per-tenant
// key via tenantKms, a real CA-signed device credential) — this is
// realistic *content* on the real app, not a separate mocked-up view.
//
// Usage:
//   npx ts-node --transpile-only scripts/seed-demo.ts
//   npx ts-node --transpile-only scripts/seed-demo.ts --reset
//   npx ts-node --transpile-only scripts/seed-demo.ts --invite demo-viewer@example.com

const DEMO_CLIENT_NAME = "Nimbus Retail (Demo)";
const DEMO_TESTER = "system:seed-demo";

async function encField(scopedKms: Awaited<ReturnType<typeof tenantKms>>, plaintext: string, aad: string) {
  return (await encryptField(scopedKms, plaintext, aad)) as unknown as object;
}

export async function resetExisting(): Promise<void> {
  const existing = await prisma.client.findFirst({ where: { name: DEMO_CLIENT_NAME } });
  if (!existing) return;

  // deleteClientData audit-logs against a real User — borrow any existing
  // SECURITY_ADMIN rather than inventing a fake user ID (AuditLog.userId is
  // a real FK; a made-up ID would just fail the insert).
  const admin = await prisma.user.findFirst({ where: { role: "SECURITY_ADMIN" } });
  if (!admin) {
    throw new Error("Cannot --reset: no SECURITY_ADMIN exists yet to attribute the deletion to. Run scripts/bootstrap-admin.ts first.");
  }

  await deleteClientData(prisma, existing.id, admin.id);
  console.log(`Removed existing demo client (id=${existing.id}) before reseeding.`);
}

export async function seedDemo(inviteEmail?: string): Promise<{ clientId: string }> {
  const existing = await prisma.client.findFirst({ where: { name: DEMO_CLIENT_NAME } });
  if (existing) {
    throw new Error(`Demo client "${DEMO_CLIENT_NAME}" already exists (id=${existing.id}). Re-run with --reset to wipe and reseed it.`);
  }

  const client = await prisma.client.create({ data: { name: DEMO_CLIENT_NAME, industry: "Retail / E-commerce" } });
  const scopedKms = await tenantKms(client.id);

  const now = Date.now();
  const daysAgo = (n: number) => new Date(now - n * 24 * 60 * 60 * 1000);

  const engagementActive = await prisma.engagement.create({
    data: {
      clientId: client.id,
      status: "ACTIVE",
      authorizedBy: "Jordan Reyes, CISO",
      authorizationSignedAt: daysAgo(14),
      authorizationMethod: "MANUAL",
      startDate: daysAgo(14),
      assumptionsEnc: await encField(scopedKms, "Testing limited to production-equivalent staging environment; no destructive testing against live payment processing.", "engagement:assumptions"),
    },
  });

  const engagementComplete = await prisma.engagement.create({
    data: {
      clientId: client.id,
      status: "CLOSED",
      authorizedBy: "Jordan Reyes, CISO",
      authorizationSignedAt: daysAgo(120),
      authorizationMethod: "MANUAL",
      startDate: daysAgo(120),
      endDate: daysAgo(95),
    },
  });

  const assetSpecs = [
    { key: "storefront", engagementId: engagementActive.id, type: "WEB" as const, name: "Storefront (www.nimbusretail-demo.example)", identifier: "https://www.nimbusretail-demo.example", criticality: "CRITICAL" as const, verified: true },
    { key: "checkoutApi", engagementId: engagementActive.id, type: "API" as const, name: "Checkout API (api.nimbusretail-demo.example)", identifier: "https://api.nimbusretail-demo.example", criticality: "CRITICAL" as const, verified: true },
    { key: "awsAccount", engagementId: engagementActive.id, type: "CLOUD" as const, name: "Primary AWS Account", identifier: "aws-account:123456789012", criticality: "HIGH" as const, verified: false },
    { key: "mobileApp", engagementId: engagementActive.id, type: "MOBILE" as const, name: "Nimbus Shopper (iOS/Android)", identifier: "com.nimbusretail.shopper", criticality: "MEDIUM" as const, verified: false },
    { key: "vpnGateway", engagementId: engagementComplete.id, type: "NETWORK" as const, name: "Corporate VPN Gateway", identifier: "203.0.113.10", criticality: "MEDIUM" as const, verified: true },
    { key: "adminServer", engagementId: engagementComplete.id, type: "SERVER" as const, name: "Internal Admin Server", identifier: "admin-internal.nimbusretail-demo.example", criticality: "HIGH" as const, verified: true },
  ];

  const assets: Record<string, { id: string; engagementId: string }> = {};
  for (const spec of assetSpecs) {
    const row = await prisma.asset.create({
      data: {
        engagementId: spec.engagementId,
        type: spec.type,
        name: spec.name,
        identifierEnc: await encField(scopedKms, spec.identifier, "asset:identifier"),
        criticality: spec.criticality,
        inScope: true,
        verificationStatus: spec.verified ? "VERIFIED" : "UNVERIFIED",
        verificationMethod: spec.verified ? "MANUAL" : null,
        verifiedAt: spec.verified ? daysAgo(13) : null,
        verifiedBy: spec.verified ? "system:seed-demo" : null,
      },
    });
    assets[spec.key] = { id: row.id, engagementId: row.engagementId };
  }

  const findingSpecs = [
    {
      assetKey: "checkoutApi", title: "SQL injection in /api/orders search filter", severity: "CRITICAL" as const, cvss: 9.8,
      description: "The `q` query parameter on GET /api/orders is concatenated directly into the backing SQL query. A crafted value returns rows outside the authenticated user's own orders and, chained with UNION-based extraction, discloses other customers' order and payment-method-reference data.",
      remediation: "Parameterize the query (prepared statements) and add an integration test asserting the endpoint rejects SQL metacharacters. Rotate any credentials the database user could have exposed.",
      status: "OPEN" as const, effort: "SMALL" as const,
    },
    {
      assetKey: "storefront", title: "Reflected XSS in storefront search parameter", severity: "HIGH" as const, cvss: 7.4,
      description: "The `?query=` parameter on /search is reflected into the page unescaped, allowing arbitrary script execution in a victim's session if they follow a crafted link.",
      remediation: "HTML-encode all reflected user input server-side, and add a Content-Security-Policy header as defense in depth.",
      status: "REMEDIATING" as const, effort: "QUICK_WIN" as const,
    },
    {
      assetKey: "awsAccount", title: "S3 bucket \"nimbus-retail-demo-assets\" permits public ListBucket", severity: "HIGH" as const, cvss: 7.5,
      description: "The bucket policy grants s3:ListBucket to the public/anonymous principal, allowing any internet user to enumerate every object key in the bucket, including ones not otherwise linked publicly.",
      remediation: "Remove the public ListBucket grant; use CloudFront with origin access control for any objects that genuinely need public read.",
      status: "OPEN" as const, effort: "QUICK_WIN" as const,
    },
    {
      assetKey: "checkoutApi", title: "Missing rate limiting on POST /api/login", severity: "MEDIUM" as const, cvss: 5.9,
      description: "No rate limiting or account lockout on the login endpoint — an attacker can attempt credential-stuffing at high volume against real customer accounts.",
      remediation: "Add per-IP and per-account rate limiting, with progressive backoff after repeated failures.",
      status: "OPEN" as const, effort: "SMALL" as const,
    },
    {
      assetKey: "storefront", title: "Verbose error responses disclose stack traces", severity: "MEDIUM" as const, cvss: 4.3,
      description: "Unhandled exceptions return the raw stack trace, including internal file paths and the ORM query that failed, to the client in production.",
      remediation: "Return a generic error response in production; log the real stack trace server-side only.",
      status: "OPEN" as const, effort: "QUICK_WIN" as const,
    },
    {
      assetKey: "storefront", title: "Missing HTTP security headers (CSP, X-Frame-Options)", severity: "LOW" as const, cvss: 3.1,
      description: "No Content-Security-Policy, X-Frame-Options, or X-Content-Type-Options headers are set, reducing defense-in-depth against XSS and clickjacking.",
      remediation: "Set the standard security header set at the reverse proxy or in application middleware.",
      status: "OPEN" as const, effort: "QUICK_WIN" as const,
    },
    {
      assetKey: "mobileApp", title: "Auth token stored in plaintext SharedPreferences (Android)", severity: "LOW" as const, cvss: 3.3,
      description: "The session token is stored unencrypted in the app's SharedPreferences file, readable by any other app with root or backup-extraction access on the same device.",
      remediation: "Store the token in the Android Keystore (or EncryptedSharedPreferences); apply the equivalent Keychain protection on iOS.",
      status: "OPEN" as const, effort: "MEDIUM" as const,
    },
    {
      assetKey: "storefront", title: "Web server banner discloses framework version", severity: "INFO" as const, cvss: 0,
      description: "The Server response header discloses the exact web framework version in use, narrowing an attacker's search for a matching known CVE.",
      remediation: "Suppress or genericize the Server header.",
      status: "ACCEPTED_RISK" as const, effort: null,
    },
    {
      assetKey: "vpnGateway", title: "Outdated TLS 1.0/1.1 still accepted", severity: "MEDIUM" as const, cvss: 5.3,
      description: "The VPN gateway's management interface still negotiates TLS 1.0 and 1.1, both deprecated and vulnerable to known downgrade/POODLE-family attacks.",
      remediation: "Disable TLS 1.0/1.1, require TLS 1.2+ only.",
      status: "RETESTED_PASS" as const, effort: "QUICK_WIN" as const,
    },
    {
      assetKey: "vpnGateway", title: "Default credentials on network switch admin panel", severity: "HIGH" as const, cvss: 8.1,
      description: "A managed switch behind the VPN gateway was reachable on its admin panel using the vendor's documented default credentials.",
      remediation: "Change all default credentials as part of device provisioning; add a check to the deployment runbook.",
      status: "RETESTED_PASS" as const, effort: "QUICK_WIN" as const,
    },
    {
      assetKey: "adminServer", title: "Outdated WordPress plugin with known RCE (CVE-2023-31199)", severity: "CRITICAL" as const, cvss: 9.1,
      description: "The internal admin server ran a WordPress plugin three major versions behind, with a publicly disclosed unauthenticated remote code execution vulnerability.",
      remediation: "Patch to the latest plugin version and enable automatic security updates for plugins on internal-only WordPress installs.",
      status: "RETESTED_PASS" as const, effort: "LARGE" as const,
    },
    {
      assetKey: "adminServer", title: "SSH exposed to 0.0.0.0/0 on internal admin server", severity: "LOW" as const, cvss: 3.7,
      description: "SSH (port 22) is reachable from any source IP rather than being restricted to the corporate VPN range, widening the brute-force attack surface.",
      remediation: "Restrict SSH ingress to the VPN CIDR range via security group/firewall rule.",
      status: "REMEDIATING" as const, effort: "SMALL" as const,
    },
  ];

  let discoveredAt = daysAgo(10);
  for (const spec of findingSpecs) {
    const asset = assets[spec.assetKey];
    const test = await prisma.test.create({
      data: {
        engagementId: asset.engagementId,
        assetId: asset.id,
        type: "PENTEST",
        methodology: "Manual (demo seed)",
        toolUsed: "Manual + Burp Suite",
        testerId: DEMO_TESTER,
        status: "COMPLETE",
        startedAt: discoveredAt,
        completedAt: discoveredAt,
      },
    });

    const finding = await prisma.finding.create({
      data: {
        testId: test.id,
        assetId: asset.id,
        title: spec.title,
        severity: spec.severity,
        cvssScore: spec.cvss,
        descriptionEnc: await encField(scopedKms, spec.description, "finding:description"),
        remediationGuidanceEnc: await encField(scopedKms, spec.remediation, "finding:remediationGuidance"),
        remediationEffort: spec.effort,
        status: spec.status,
        discoveredAt,
      },
    });

    if (spec.status === "RETESTED_PASS") {
      await prisma.retest.create({
        data: {
          findingId: finding.id,
          retestedBy: DEMO_TESTER,
          result: "FIXED",
          retestedAt: daysAgo(2),
          notesEnc: await encField(scopedKms, "Retested and confirmed remediated.", "retest:notes"),
        },
      });
    }

    discoveredAt = new Date(discoveredAt.getTime() + 6 * 60 * 60 * 1000); // stagger by 6h so ordering looks realistic
  }

  // Compliance — ISO27001, a realistic mix of statuses
  const complianceSpecs: { controlId: string; controlName: string; status: "PASS" | "FAIL" | "PARTIAL" | "PENDING" }[] = [
    { controlId: "A.5.1", controlName: "Policies for information security", status: "PASS" },
    { controlId: "A.8.1", controlName: "Inventory of information and other associated assets", status: "PARTIAL" },
    { controlId: "A.8.24", controlName: "Use of cryptography", status: "PASS" },
    { controlId: "A.8.9", controlName: "Configuration management", status: "FAIL" },
    { controlId: "A.5.23", controlName: "Information security for use of cloud services", status: "FAIL" },
    { controlId: "A.6.3", controlName: "Information security awareness, education and training", status: "PENDING" },
  ];
  for (const c of complianceSpecs) {
    await prisma.complianceCheck.create({
      data: {
        engagementId: engagementActive.id,
        framework: "ISO27001",
        controlId: c.controlId,
        controlName: c.controlName,
        status: c.status,
        notesEnc:
          c.status === "FAIL"
            ? await encField(scopedKms, "Gap identified during this engagement — see linked findings.", "compliance:notes")
            : null,
      },
    });
  }

  // Staff training
  await prisma.trainingSession.create({
    data: {
      engagementId: engagementActive.id,
      topic: "PHISHING",
      scheduledAt: daysAgo(8),
      status: "COMPLETED",
      attendeeCount: 24,
      notesEnc: await encField(scopedKms, "Simulated phishing campaign + live session. Click rate dropped from 18% (baseline) to 4% on the follow-up test.", "training:notes"),
    },
  });

  // Discovery + watch mode — one already-reviewed discovery run, plus a
  // fresh watch-mode alert waiting for review, so both surfaces have content.
  const discoveryJob = await prisma.discoveryJob.create({
    data: {
      engagementId: engagementActive.id,
      assetId: assets.storefront.id,
      tool: "passive-discovery",
      status: "COMPLETE",
      triggeredById: DEMO_TESTER,
      startedAt: daysAgo(5),
      completedAt: daysAgo(5),
      discoveredCount: 1,
    },
  });
  const discoveredAsset = await prisma.discoveredAsset.create({
    data: {
      engagementId: engagementActive.id,
      parentAssetId: assets.storefront.id,
      discoveryJobId: discoveryJob.id,
      valueEnc: await encField(scopedKms, "staging.nimbusretail-demo.example", "discoveredAsset:value"),
      source: "crt.sh",
      openPorts: [443],
      status: "NEW",
    },
  });
  await prisma.watchAlert.create({
    data: {
      engagementId: engagementActive.id,
      discoveredAssetId: discoveredAsset.id,
      discoveryJobId: discoveryJob.id,
      kind: "NEW_SUBDOMAIN",
      summary: "New subdomain discovered under storefront's root domain",
      createdAt: daysAgo(1),
    },
  });

  // Endpoint agent — a real, internally-consistent Ed25519 device
  // credential (same primitives as real enrollment, src/modules/agents/ca.ts)
  // rather than placeholder strings, so this demo device would actually
  // pass verifyDeviceSignature if exercised for real.
  const deviceId = crypto.randomUUID();
  const { publicKey, privateKey: _unused } = crypto.generateKeyPairSync("ed25519");
  const pubJwk = publicKey.export({ format: "jwk" }) as { x: string };
  const devicePublicKeyBase64 = Buffer.from(pubJwk.x, "base64url").toString("base64");
  const issuedAt = Math.floor(daysAgo(20).getTime() / 1000);
  const credentialSig = await signCredential(deviceId, client.id, devicePublicKeyBase64, issuedAt);

  await prisma.device.create({
    data: {
      id: deviceId,
      clientId: client.id,
      name: "web-prod-01",
      platform: "linux",
      publicKeyBase64: devicePublicKeyBase64,
      credentialSig,
      status: "ACTIVE",
      enrolledAt: daysAgo(20),
      lastCheckInAt: daysAgo(0.1),
      osVersion: "Ubuntu 22.04.4 LTS",
      lastInventoryEnc: await encField(
        scopedKms,
        JSON.stringify({
          os: { name: "Ubuntu", version: "22.04.4 LTS" },
          software: [
            { name: "nginx", version: "1.24.0" },
            { name: "openssh-server", version: "8.9p1" },
            { name: "docker-ce", version: "24.0.7" },
          ],
          processes: [{ name: "nginx" }, { name: "dockerd" }, { name: "sshd" }],
          firewall: "ENABLED",
          interfaces: [{ name: "eth0", ip: "10.0.4.12" }],
          collectedAt: Date.now(),
        }),
        "device:lastInventory"
      ),
    },
  });

  // Optional: invite a real person to view this as a client-side user, the
  // same real Clerk-invite path bootstrap-admin.ts uses.
  if (inviteEmail) {
    const existingUser = await prisma.user.findUnique({ where: { email: inviteEmail } });
    if (!existingUser) {
      await prisma.user.create({ data: { name: "Demo Viewer", email: inviteEmail, role: "EXEC_CLIENT", orgId: client.id } });
      try {
        await clerkClient.invitations.createInvitation({ emailAddress: inviteEmail, notify: true, ignoreExisting: true });
        console.log(`Invited ${inviteEmail} as EXEC_CLIENT on the demo org.`);
      } catch (err) {
        console.warn(`User row created, but the Clerk invitation failed: ${err instanceof Error ? err.message : err}`);
      }
    } else {
      console.log(`${inviteEmail} already exists as a user (id=${existingUser.id}) — left as-is.`);
    }
  }

  return { clientId: client.id };
}

async function cli() {
  const args = process.argv.slice(2);
  if (args.includes("--reset")) {
    await resetExisting();
  }
  const inviteFlagIndex = args.indexOf("--invite");
  const inviteEmail = inviteFlagIndex !== -1 ? args[inviteFlagIndex + 1] : undefined;

  const { clientId } = await seedDemo(inviteEmail);
  console.log(`Seeded demo client "${DEMO_CLIENT_NAME}" (id=${clientId}).`);
  console.log("6 assets, 12 findings across every severity, 3 retests, 6 compliance checks, 1 training session,");
  console.log("1 discovered asset + watch alert, and 1 endpoint agent device.");
}

if (require.main === module) {
  cli()
    .catch((err) => {
      console.error("Demo seed failed:", err);
      process.exit(1);
    })
    .finally(() => prisma.$disconnect());
}
