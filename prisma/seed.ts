import "dotenv/config";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// Clerk requires a real, verifiable email to sign up with — the old
// "admin@jupiter.local" fake demo address can't actually be used to create
// a Clerk account. This seeds a User row (role/orgId — our authorization
// data) keyed to a real email; sign up in Clerk with that same email and
// requireAuth (src/middleware/auth.ts) will resolve you to this row.
const ADMIN_EMAIL = process.env.SEED_ADMIN_EMAIL ?? "anothersalako@gmail.com";

async function main() {
  const admin = await prisma.user.upsert({
    where: { email: ADMIN_EMAIL },
    update: { role: "SECURITY_ADMIN" },
    create: { name: "Security Admin", email: ADMIN_EMAIL, role: "SECURITY_ADMIN" },
  });

  const client = await prisma.client.upsert({
    where: { id: "00000000-0000-0000-0000-000000000001" },
    update: {},
    create: {
      id: "00000000-0000-0000-0000-000000000001",
      name: "Acme Demo Corp",
      industry: "Fintech",
    },
  });

  console.log("Seeded:");
  console.log(`  security_admin: ${admin.email}  (id=${admin.id}) — sign up in Clerk with this exact email`);
  console.log(`  client:         ${client.name} (id=${client.id})`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => prisma.$disconnect());
