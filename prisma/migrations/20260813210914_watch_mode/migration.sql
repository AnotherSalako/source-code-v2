-- CreateEnum
CREATE TYPE "WatchAlertKind" AS ENUM ('NEW_SUBDOMAIN', 'PORT_OPENED', 'PORT_CLOSED', 'SERVICE_CHANGED');

-- AlterTable
ALTER TABLE "DiscoveredAsset" ADD COLUMN     "lastScannedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "WatchAlert" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "discoveredAssetId" TEXT,
    "discoveryJobId" TEXT NOT NULL,
    "kind" "WatchAlertKind" NOT NULL,
    "summary" TEXT NOT NULL,
    "details" JSONB,
    "acknowledgedAt" TIMESTAMP(3),
    "acknowledgedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WatchAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "WatchAlert_engagementId_idx" ON "WatchAlert"("engagementId");

-- CreateIndex
CREATE INDEX "WatchAlert_discoveredAssetId_idx" ON "WatchAlert"("discoveredAssetId");

-- CreateIndex
CREATE INDEX "WatchAlert_discoveryJobId_idx" ON "WatchAlert"("discoveryJobId");

-- AddForeignKey
ALTER TABLE "WatchAlert" ADD CONSTRAINT "WatchAlert_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WatchAlert" ADD CONSTRAINT "WatchAlert_discoveredAssetId_fkey" FOREIGN KEY ("discoveredAssetId") REFERENCES "DiscoveredAsset"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WatchAlert" ADD CONSTRAINT "WatchAlert_discoveryJobId_fkey" FOREIGN KEY ("discoveryJobId") REFERENCES "DiscoveryJob"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
