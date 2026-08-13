import "dotenv/config";
import { clerkClient } from "@clerk/express";
import { prisma } from "../src/db/prisma";

// Solves the chicken-and-egg problem on a brand-new deployment: POST /users
// (the normal way to grant access) requires an existing SECURITY_ADMIN to
// call it, and a fresh database has none. Run this ONCE, right after the
// first `prisma migrate deploy` against a new environment, to create that
// first admin — after that, every subsequent user (including more admins)
// goes through the normal POST /users flow like it should.
//
// Usage: npx ts-node --transpile-only scripts/bootstrap-admin.ts "Jane Doe" jane@example.com

export type BootstrapResult =
  | { status: "created"; userId: string; invitationSent: boolean; invitationError?: string }
  | { status: "refused"; reason: string };

export async function bootstrapAdmin(name: string, email: string): Promise<BootstrapResult> {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { status: "refused", reason: `"${email}" doesn't look like a valid email address.` };
  }

  // The safety rail: this bypasses requireRole("SECURITY_ADMIN") entirely
  // (nothing else can, by design), so it must refuse to become an ad-hoc
  // admin-creation backdoor on a deployment that's already past its first
  // setup. If this fires, use the app's own Team page / POST /users instead
  // — that's the real, audited path once at least one admin exists.
  const existingAdminCount = await prisma.user.count({ where: { role: "SECURITY_ADMIN" } });
  if (existingAdminCount > 0) {
    return {
      status: "refused",
      reason:
        `This deployment already has ${existingAdminCount} SECURITY_ADMIN account(s). ` +
        "Bootstrap is only for a brand-new deployment's very first admin — use the app's Team page " +
        "(or POST /users, as an existing admin) to add more.",
    };
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return { status: "refused", reason: `A user with email ${email} already exists (id=${existing.id}, role=${existing.role}).` };
  }

  const user = await prisma.user.create({ data: { name, email, role: "SECURITY_ADMIN", orgId: null } });

  let invitationSent = false;
  let invitationError: string | undefined;
  try {
    await clerkClient.invitations.createInvitation({ emailAddress: email, notify: true, ignoreExisting: true });
    invitationSent = true;
  } catch (err) {
    invitationError = err instanceof Error ? err.message : "Unknown error sending Clerk invitation";
  }

  return { status: "created", userId: user.id, invitationSent, invitationError };
}

async function cli() {
  const [name, email] = process.argv.slice(2);
  if (!name || !email) {
    console.error('Usage: npx ts-node --transpile-only scripts/bootstrap-admin.ts "Full Name" email@example.com');
    process.exit(1);
  }

  const result = await bootstrapAdmin(name, email);

  if (result.status === "refused") {
    console.error(`Refusing to run: ${result.reason}`);
    process.exit(1);
  }

  console.log(`Created SECURITY_ADMIN: ${name} <${email}> (id=${result.userId})`);
  if (result.invitationSent) {
    console.log("Clerk invitation sent — they'll get an email to set up sign-in.");
  } else {
    console.warn(
      `Clerk invitation was NOT sent (${result.invitationError}). ` +
        "Check CLERK_SECRET_KEY is set for this environment, or invite them manually from the Clerk dashboard " +
        "— they still need a real Clerk account before they can sign in, this User row alone isn't enough."
    );
  }
}

// Only run the CLI when this file is executed directly (`ts-node
// scripts/bootstrap-admin.ts`), not when the test suite imports
// bootstrapAdmin() from it.
if (require.main === module) {
  cli()
    .catch((err) => {
      console.error("Bootstrap failed:", err);
      process.exit(1);
    })
    .finally(() => prisma.$disconnect());
}
