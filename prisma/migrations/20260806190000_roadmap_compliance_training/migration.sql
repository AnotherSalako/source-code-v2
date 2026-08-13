-- AlterEnum
ALTER TYPE "ComplianceStatus" ADD VALUE 'PENDING';

-- CreateEnum
CREATE TYPE "RemediationEffort" AS ENUM ('QUICK_WIN', 'SMALL', 'MEDIUM', 'LARGE');

-- CreateEnum
CREATE TYPE "TrainingTopic" AS ENUM ('PHISHING', 'PASSWORD_HYGIENE', 'DATA_HANDLING', 'APP_INFRA_MISTAKES', 'CUSTOM');

-- CreateEnum
CREATE TYPE "TrainingStatus" AS ENUM ('SCHEDULED', 'COMPLETED', 'CANCELLED');

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN "remediationEffort" "RemediationEffort";

-- CreateTable
CREATE TABLE "TrainingSession" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "topic" "TrainingTopic" NOT NULL,
    "customTopic" TEXT,
    "scheduledAt" TIMESTAMP(3) NOT NULL,
    "status" "TrainingStatus" NOT NULL DEFAULT 'SCHEDULED',
    "attendeeCount" INTEGER,
    "notesEnc" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TrainingSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TrainingSession_engagementId_idx" ON "TrainingSession"("engagementId");

-- AddForeignKey
ALTER TABLE "TrainingSession" ADD CONSTRAINT "TrainingSession_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
