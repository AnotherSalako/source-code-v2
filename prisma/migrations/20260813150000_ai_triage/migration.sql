-- CreateEnum
CREATE TYPE "FalsePositiveLikelihood" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN "aiRemediationDraftEnc" JSONB;
ALTER TABLE "Finding" ADD COLUMN "aiFalsePositiveLikelihood" "FalsePositiveLikelihood";
ALTER TABLE "Finding" ADD COLUMN "aiTriageRationaleEnc" JSONB;
ALTER TABLE "Finding" ADD COLUMN "aiTriagedAt" TIMESTAMP(3);
