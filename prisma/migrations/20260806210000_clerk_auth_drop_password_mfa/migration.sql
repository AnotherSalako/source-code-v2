-- AlterTable: identity/credentials/MFA now live in Clerk, not this table.
ALTER TABLE "User" DROP COLUMN "passwordHash";
ALTER TABLE "User" DROP COLUMN "mfaEnabled";
ALTER TABLE "User" DROP COLUMN "mfaSecretEnc";
