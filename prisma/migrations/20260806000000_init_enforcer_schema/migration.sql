-- CreateEnum
CREATE TYPE "Role" AS ENUM ('EXEC_CLIENT', 'TECHNICAL_CLIENT', 'SECURITY_ADMIN');

-- CreateEnum
CREATE TYPE "EngagementStatus" AS ENUM ('SCOPING', 'ACTIVE', 'REPORTING', 'RETEST', 'CLOSED');

-- CreateEnum
CREATE TYPE "AssetType" AS ENUM ('WEB', 'MOBILE', 'SERVER', 'CLOUD', 'NETWORK', 'API');

-- CreateEnum
CREATE TYPE "Criticality" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "TestType" AS ENUM ('VULN_SCAN', 'PENTEST', 'COMPLIANCE_REVIEW');

-- CreateEnum
CREATE TYPE "TestStatus" AS ENUM ('PLANNED', 'IN_PROGRESS', 'COMPLETE');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'REMEDIATING', 'RETESTED_PASS', 'RETESTED_FAIL', 'ACCEPTED_RISK');

-- CreateEnum
CREATE TYPE "ComplianceFramework" AS ENUM ('NDPR', 'ISO27001', 'PCI_DSS', 'OTHER');

-- CreateEnum
CREATE TYPE "ComplianceStatus" AS ENUM ('PASS', 'FAIL', 'PARTIAL', 'NOT_APPLICABLE');

-- CreateEnum
CREATE TYPE "ReportType" AS ENUM ('EXECUTIVE', 'TECHNICAL', 'RETEST_ADDENDUM');

-- CreateEnum
CREATE TYPE "RetestResult" AS ENUM ('FIXED', 'NOT_FIXED', 'PARTIALLY_FIXED');

-- CreateEnum
CREATE TYPE "KeyPurpose" AS ENUM ('DB_FIELD', 'FILE');

-- CreateEnum
CREATE TYPE "KeyStatus" AS ENUM ('ACTIVE', 'RETIRED', 'REVOKED');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('VIEW', 'CREATE', 'UPDATE', 'DELETE', 'DOWNLOAD', 'DECRYPT', 'LOGIN', 'LOGIN_FAILED');

-- CreateEnum
CREATE TYPE "AuditResult" AS ENUM ('SUCCESS', 'DENIED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "orgId" TEXT,
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Client" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "industry" TEXT,
    "primaryContactEnc" JSONB,
    "billingInfoEnc" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Client_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Engagement" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "status" "EngagementStatus" NOT NULL DEFAULT 'SCOPING',
    "scopeDocRef" TEXT,
    "assumptionsEnc" JSONB,
    "exclusionsEnc" JSONB,
    "authorizedBy" TEXT,
    "authorizationSignedAt" TIMESTAMP(3),
    "authorizationDocRef" TEXT,
    "startDate" TIMESTAMP(3),
    "endDate" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Engagement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Asset" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "type" "AssetType" NOT NULL,
    "name" TEXT NOT NULL,
    "identifierEnc" JSONB NOT NULL,
    "owner" TEXT,
    "criticality" "Criticality" NOT NULL DEFAULT 'MEDIUM',
    "inScope" BOOLEAN NOT NULL DEFAULT true,
    "notesEnc" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Asset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Test" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "type" "TestType" NOT NULL,
    "methodology" TEXT,
    "toolUsed" TEXT,
    "testerId" TEXT,
    "status" "TestStatus" NOT NULL DEFAULT 'PLANNED',
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Test_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "testId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "descriptionEnc" JSONB NOT NULL,
    "severity" "Severity" NOT NULL,
    "cvssScore" DOUBLE PRECISION,
    "reproductionStepsEnc" JSONB,
    "remediationGuidanceEnc" JSONB,
    "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "discoveredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Evidence" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "originalFilename" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "iv" TEXT NOT NULL,
    "authTag" TEXT NOT NULL,
    "encryptedDataKey" TEXT NOT NULL,
    "kmsKeyId" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "uploadedBy" TEXT NOT NULL,
    "uploadedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComplianceCheck" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "framework" "ComplianceFramework" NOT NULL,
    "controlId" TEXT NOT NULL,
    "controlName" TEXT NOT NULL,
    "status" "ComplianceStatus" NOT NULL,
    "notesEnc" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ComplianceCheck_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "type" "ReportType" NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "storageKey" TEXT NOT NULL,
    "iv" TEXT NOT NULL,
    "authTag" TEXT NOT NULL,
    "encryptedDataKey" TEXT NOT NULL,
    "kmsKeyId" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "generatedBy" TEXT NOT NULL,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Retest" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "retestedBy" TEXT NOT NULL,
    "retestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "result" "RetestResult" NOT NULL,
    "notesEnc" JSONB,

    CONSTRAINT "Retest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KeyRef" (
    "id" TEXT NOT NULL,
    "purpose" "KeyPurpose" NOT NULL,
    "kmsKeyId" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "status" "KeyStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retiredAt" TIMESTAMP(3),

    CONSTRAINT "KeyRef_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "action" "AuditAction" NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT,
    "engagementId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "result" "AuditResult" NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_orgId_idx" ON "User"("orgId");

-- CreateIndex
CREATE INDEX "Engagement_clientId_idx" ON "Engagement"("clientId");

-- CreateIndex
CREATE INDEX "Asset_engagementId_idx" ON "Asset"("engagementId");

-- CreateIndex
CREATE INDEX "Test_engagementId_idx" ON "Test"("engagementId");

-- CreateIndex
CREATE INDEX "Test_assetId_idx" ON "Test"("assetId");

-- CreateIndex
CREATE INDEX "Finding_testId_idx" ON "Finding"("testId");

-- CreateIndex
CREATE INDEX "Finding_assetId_idx" ON "Finding"("assetId");

-- CreateIndex
CREATE INDEX "Evidence_findingId_idx" ON "Evidence"("findingId");

-- CreateIndex
CREATE INDEX "ComplianceCheck_engagementId_idx" ON "ComplianceCheck"("engagementId");

-- CreateIndex
CREATE INDEX "Report_engagementId_idx" ON "Report"("engagementId");

-- CreateIndex
CREATE INDEX "Retest_findingId_idx" ON "Retest"("findingId");

-- CreateIndex
CREATE INDEX "KeyRef_resourceType_resourceId_idx" ON "KeyRef"("resourceType", "resourceId");

-- CreateIndex
CREATE INDEX "KeyRef_status_idx" ON "KeyRef"("status");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_resourceType_resourceId_idx" ON "AuditLog"("resourceType", "resourceId");

-- CreateIndex
CREATE INDEX "AuditLog_timestamp_idx" ON "AuditLog"("timestamp");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Client"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Engagement" ADD CONSTRAINT "Engagement_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Asset" ADD CONSTRAINT "Asset_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Test" ADD CONSTRAINT "Test_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Test" ADD CONSTRAINT "Test_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_testId_fkey" FOREIGN KEY ("testId") REFERENCES "Test"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ComplianceCheck" ADD CONSTRAINT "ComplianceCheck_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Retest" ADD CONSTRAINT "Retest_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

