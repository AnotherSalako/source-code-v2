import { NextFunction, Request, Response } from "express";
import { getAuth, clerkClient } from "@clerk/express";
import { prisma } from "../db/prisma";

/**
 * Clerk owns identity: who you are, your password, your MFA. This app still
 * owns authorization: what you're allowed to do (role, which client org you
 * belong to) — that's business data Clerk has no notion of. The bridge is
 * the email address: a Clerk-verified request is looked up in our own
 * `User` table by email to resolve role/orgId, and `req.user` ends up with
 * exactly the same shape it always did, so every route/RBAC check downstream
 * (`requireRole`, `assertOwnOrg`, etc.) is unchanged by this being Clerk
 * underneath instead of our own JWT.
 *
 * Requires `clerkMiddleware()` mounted earlier in app.ts — that's what
 * populates what `getAuth(req)` reads.
 */

// clerkClient.users.getUser() is a live network call to Clerk's API — left
// uncached, that's ~1-2s added to *every single* authenticated request,
// including repeats for the same signed-in user seconds apart (measured
// live: every request, not just the first, paid this cost). A user's email
// essentially never changes mid-session, so a short TTL cache turns N
// network round-trips into 1 per user per window without weakening
// anything Clerk actually verifies (the session token itself is still
// checked fresh by clerkMiddleware() on every request via getAuth()).
const EMAIL_CACHE_TTL_MS = 5 * 60 * 1000;
const emailCache = new Map<string, { email: string; expiresAt: number }>();

async function resolveEmail(userId: string): Promise<string | undefined> {
  const cached = emailCache.get(userId);
  if (cached && cached.expiresAt > Date.now()) return cached.email;

  const clerkUser = await clerkClient.users.getUser(userId);
  const email = clerkUser.primaryEmailAddress?.emailAddress ?? clerkUser.emailAddresses[0]?.emailAddress;
  if (email) emailCache.set(userId, { email, expiresAt: Date.now() + EMAIL_CACHE_TTL_MS });
  return email;
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const { userId } = getAuth(req);
  if (!userId) {
    res.status(401).json({ error: "Not signed in" });
    return;
  }

  const email = await resolveEmail(userId);
  if (!email) {
    res.status(403).json({ error: "Your Clerk account has no email address on file" });
    return;
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    res.status(403).json({ error: "This account isn't provisioned in Enforcer yet — ask an administrator to add you." });
    return;
  }

  req.user = { id: user.id, role: user.role, orgId: user.orgId };
  next();
}
