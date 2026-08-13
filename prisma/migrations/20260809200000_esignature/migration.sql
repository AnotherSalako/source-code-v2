-- CreateEnum
CREATE TYPE "AuthorizationMethod" AS ENUM ('MANUAL', 'ESIGNATURE');

-- CreateEnum
CREATE TYPE "AuthorizationRequestStatus" AS ENUM ('SENT', 'SIGNED', 'DECLINED', 'VOIDED');

-- AlterTable
ALTER TABLE "Engagement" ADD COLUMN "authorizationDocIv" TEXT;
ALTER TABLE "Engagement" ADD COLUMN "authorizationDocAuthTag" TEXT;
ALTER TABLE "Engagement" ADD COLUMN "authorizationDocEncryptedDataKey" TEXT;
ALTER TABLE "Engagement" ADD COLUMN "authorizationDocKmsKeyId" TEXT;
ALTER TABLE "Engagement" ADD COLUMN "authorizationDocKeyVersion" INTEGER;
ALTER TABLE "Engagement" ADD COLUMN "authorizationMethod" "AuthorizationMethod";
ALTER TABLE "Engagement" ADD COLUMN "authorizationEnvelopeId" TEXT;
ALTER TABLE "Engagement" ADD COLUMN "authorizationRequestStatus" "AuthorizationRequestStatus";
