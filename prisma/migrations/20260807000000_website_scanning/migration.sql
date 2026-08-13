-- CreateEnum
CREATE TYPE "VerificationMethod" AS ENUM ('DNS_TXT', 'HTTP_FILE', 'MANUAL');

-- CreateEnum
CREATE TYPE "VerificationStatus" AS ENUM ('UNVERIFIED', 'PENDING', 'VERIFIED');

-- CreateEnum
CREATE TYPE "ScanJobStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETE', 'FAILED');

-- AlterTable
ALTER TABLE "Asset" ADD COLUMN "verificationStatus" "VerificationStatus" NOT NULL DEFAULT 'UNVERIFIED';
ALTER TABLE "Asset" ADD COLUMN "verificationMethod" "VerificationMethod";
ALTER TABLE "Asset" ADD COLUMN "verificationToken" TEXT;
ALTER TABLE "Asset" ADD COLUMN "verifiedAt" TIMESTAMP(3);
ALTER TABLE "Asset" ADD COLUMN "verifiedBy" TEXT;

-- CreateTable
CREATE TABLE "ScanJob" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "testId" TEXT,
    "tool" TEXT NOT NULL DEFAULT 'nuclei',
    "status" "ScanJobStatus" NOT NULL DEFAULT 'QUEUED',
    "triggeredById" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "errorMessage" TEXT,
    "findingsCreated" INTEGER,
    "findingsSkipped" INTEGER,
    "rawResultEnc" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ScanJob_engagementId_idx" ON "ScanJob"("engagementId");

-- CreateIndex
CREATE INDEX "ScanJob_assetId_idx" ON "ScanJob"("assetId");

-- CreateIndex
CREATE INDEX "ScanJob_status_idx" ON "ScanJob"("status");

-- AddForeignKey
ALTER TABLE "ScanJob" ADD CONSTRAINT "ScanJob_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanJob" ADD CONSTRAINT "ScanJob_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanJob" ADD CONSTRAINT "ScanJob_testId_fkey" FOREIGN KEY ("testId") REFERENCES "Test"("id") ON DELETE SET NULL ON UPDATE CASCADE;
