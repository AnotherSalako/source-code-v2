-- CreateEnum
CREATE TYPE "DeviceStatus" AS ENUM ('ACTIVE', 'REVOKED');

-- CreateTable
CREATE TABLE "AgentCaKey" (
    "id" TEXT NOT NULL DEFAULT 'default',
    "publicKeyBase64" TEXT NOT NULL,
    "privateSeedEnc" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentCaKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnrollmentToken" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "usedByDeviceId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EnrollmentToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "publicKeyBase64" TEXT NOT NULL,
    "credentialSig" TEXT NOT NULL,
    "status" "DeviceStatus" NOT NULL DEFAULT 'ACTIVE',
    "enrolledAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastCheckInAt" TIMESTAMP(3),
    "osVersion" TEXT,
    "revokedAt" TIMESTAMP(3),
    "revokedBy" TEXT,

    CONSTRAINT "Device_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EnrollmentToken_tokenHash_key" ON "EnrollmentToken"("tokenHash");

-- CreateIndex
CREATE INDEX "EnrollmentToken_clientId_idx" ON "EnrollmentToken"("clientId");

-- CreateIndex
CREATE INDEX "EnrollmentToken_tokenHash_idx" ON "EnrollmentToken"("tokenHash");

-- CreateIndex
CREATE INDEX "Device_clientId_idx" ON "Device"("clientId");

-- CreateIndex
CREATE INDEX "Device_status_idx" ON "Device"("status");

-- AddForeignKey
ALTER TABLE "EnrollmentToken" ADD CONSTRAINT "EnrollmentToken_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Device" ADD CONSTRAINT "Device_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
