import { Router } from "express";
import crypto from "crypto";
import { z } from "zod";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { sideEffectLimiter } from "../../middleware/rate-limit";
import { writeAuditLog } from "../audit/audit.service";
import { caPublicKeyBase64, signCredential } from "./ca";
import { requireDeviceAuth } from "./device-auth.middleware";
import { recordUsageEvent } from "../usage/usage.service";

export const agentsRouter = Router();

const ENROLLMENT_TOKEN_TTL_MS = 30 * 60 * 1000;

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// --- Admin: generate a single-use enrollment token --------------------------
// The plaintext token is returned exactly once, in this response, and never
// stored anywhere — only its hash is persisted (EnrollmentToken.tokenHash),
// so a database compromise alone yields no usable token. Whoever is
// installing the agent needs this value copied onto the target machine
// within the TTL; there is deliberately no "show me that token again" route.
agentsRouter.post(
  "/clients/:clientId/devices/enrollment-tokens",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  sideEffectLimiter,
  async (req, res) => {
    const { clientId } = req.params;
    const client = await prisma.client.findUnique({ where: { id: clientId } });
    if (!client) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const token = crypto.randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + ENROLLMENT_TOKEN_TTL_MS);

    await prisma.enrollmentToken.create({
      data: { clientId, tokenHash: hashToken(token), createdBy: req.user!.id, expiresAt },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "enrollmentToken",
      resourceId: null,
      result: "SUCCESS",
    });

    res.status(201).json({ token, expiresAt });
  }
);

// --- Agent: redeem a token, become an enrolled Device -----------------------
const enrollSchema = z.object({
  token: z.string().min(1),
  publicKeyBase64: z.string().min(1),
  hostname: z.string().trim().min(1).max(255),
  platform: z.enum(["windows", "macos", "linux"]),
  osVersion: z.string().max(255).optional(),
});

agentsRouter.post("/internal/agents/enroll", sideEffectLimiter, async (req, res) => {
  const parsed = enrollSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { token, publicKeyBase64, hostname, platform, osVersion } = parsed.data;
  const tokenHash = hashToken(token);

  // Early exit outside the transaction so an obviously-dead token never
  // costs a signature — the transaction below is what actually prevents a
  // race between two simultaneous redemptions, this is just a fast path.
  const preCheck = await prisma.enrollmentToken.findUnique({ where: { tokenHash } });
  if (!preCheck || preCheck.usedAt || preCheck.expiresAt < new Date()) {
    await writeAuditLog(prisma, { userId: null, action: "CREATE", resourceType: "device.enroll", resourceId: null, result: "DENIED" });
    res.status(401).json({ error: "Invalid, expired, or already-used enrollment token" });
    return;
  }

  const deviceId = crypto.randomUUID();
  const issuedAt = Math.floor(Date.now() / 1000);
  const credentialSig = await signCredential(deviceId, preCheck.clientId, publicKeyBase64, issuedAt);

  // The actual race guard: re-check-and-consume atomically. If two requests
  // for the same token land concurrently, only one transaction observes
  // usedAt === null and commits; the other sees it already used and no-ops.
  const result = await prisma.$transaction(async (tx) => {
    const record = await tx.enrollmentToken.findUnique({ where: { tokenHash } });
    if (!record || record.usedAt || record.expiresAt < new Date()) return null;

    const device = await tx.device.create({
      data: { id: deviceId, clientId: record.clientId, name: hostname, platform, publicKeyBase64, osVersion, credentialSig },
    });
    await tx.enrollmentToken.update({ where: { id: record.id }, data: { usedAt: new Date(), usedByDeviceId: device.id } });
    return device;
  });

  if (!result) {
    await writeAuditLog(prisma, { userId: null, action: "CREATE", resourceType: "device.enroll", resourceId: null, result: "DENIED" });
    res.status(401).json({ error: "Invalid, expired, or already-used enrollment token" });
    return;
  }

  await writeAuditLog(prisma, {
    userId: null,
    action: "CREATE",
    resourceType: "device.enroll",
    resourceId: result.id,
    result: "SUCCESS",
  });

  res.status(201).json({
    deviceId: result.id,
    clientId: result.clientId,
    issuedAt,
    credentialSignature: credentialSig,
    caPublicKeyBase64: await caPublicKeyBase64(),
  });
});

// --- Admin: list / revoke devices -------------------------------------------
agentsRouter.get("/clients/:clientId/devices", requireAuth, async (req, res) => {
  const { clientId } = req.params;
  if (!assertOwnOrg(req, clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const devices = await prisma.device.findMany({
    where: { clientId },
    select: { id: true, name: true, platform: true, status: true, enrolledAt: true, lastCheckInAt: true, osVersion: true },
    orderBy: { enrolledAt: "desc" },
  });

  res.json(devices);
});

agentsRouter.patch("/devices/:id/revoke", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const device = await prisma.device.findUnique({ where: { id: req.params.id } });
  if (!device) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  await prisma.device.update({
    where: { id: device.id },
    data: { status: "REVOKED", revokedAt: new Date(), revokedBy: req.user!.id },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "UPDATE",
    resourceType: "device.revoke",
    resourceId: device.id,
    result: "SUCCESS",
  });

  res.json({ id: device.id, status: "REVOKED" });
});

// --- Agent: self-test that the signed-credential round trip actually works --
// This exists so enrollment is provably complete end to end: a device that
// can successfully call this has proven its private key, its stored public
// key, and requireDeviceAuth all agree.
agentsRouter.get("/internal/agents/whoami", requireDeviceAuth, async (req, res) => {
  await prisma.device.update({ where: { id: req.device!.id }, data: { lastCheckInAt: new Date() } });
  res.json({ deviceId: req.device!.id, clientId: req.device!.clientId });
});

// --- Agent: read-only inventory check-in ------------------------------------
// Array sizes are capped — defense in depth against a misbehaving or
// compromised agent sending an unbounded payload, same reasoning as the
// findings-import item cap elsewhere in this app. Latest-only: this
// overwrites Device.lastInventoryEnc rather than appending to a history —
// see schema.prisma for why a real history table is deliberately deferred.
const inventorySchema = z.object({
  os: z.object({
    name: z.string().max(200),
    version: z.string().max(200),
    build: z.string().max(200).optional(),
  }),
  software: z.array(z.object({ name: z.string().max(500), version: z.string().max(200).optional() })).max(5000),
  processes: z.array(z.object({ name: z.string().max(500) })).max(2000),
  firewall: z.enum(["ENABLED", "DISABLED", "UNAVAILABLE"]),
  interfaces: z.array(z.object({ name: z.string().max(200), ip: z.string().max(100) })).max(50),
  collectedAt: z.number(),
});

agentsRouter.post("/internal/agents/checkin", requireDeviceAuth, async (req, res) => {
  const parsed = inventorySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const scopedKms = await tenantKms(req.device!.clientId);

  await prisma.device.update({
    where: { id: req.device!.id },
    data: {
      lastCheckInAt: new Date(),
      lastInventoryEnc: (await encryptField(scopedKms, JSON.stringify(parsed.data), `device:lastInventory`)) as any,
      osVersion: `${parsed.data.os.name} ${parsed.data.os.version}`,
    },
  });

  await writeAuditLog(prisma, {
    userId: null,
    action: "UPDATE",
    resourceType: "device.checkin",
    resourceId: req.device!.id,
    result: "SUCCESS",
  });

  await recordUsageEvent(req.device!.clientId, "AGENT_CHECK_IN");

  res.json({ received: true });
});

// --- Admin: read a device's latest inventory --------------------------------
// Same sensitivity tier as scan-jobs' rawResult / evidence — decrypting it
// is logged (DECRYPT), not just the request itself.
agentsRouter.get("/devices/:id/inventory", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const device = await prisma.device.findUnique({ where: { id: req.params.id } });
  if (!device || !assertOwnOrg(req, device.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  if (!device.lastInventoryEnc) {
    res.json({ inventory: null, collectedAt: null });
    return;
  }

  const raw = await decryptField(kms, device.lastInventoryEnc as any, `device:lastInventory`);

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DECRYPT",
    resourceType: "device.inventory",
    resourceId: device.id,
    result: "SUCCESS",
  });

  res.json({ inventory: JSON.parse(raw), collectedAt: device.lastCheckInAt });
});
