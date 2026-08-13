-- CreateEnum
CREATE TYPE "DiscoveredAssetStatus" AS ENUM ('NEW', 'PROMOTED', 'IGNORED');

-- CreateTable
CREATE TABLE "DiscoveryJob" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "tool" TEXT NOT NULL DEFAULT 'passive-discovery',
    "status" "ScanJobStatus" NOT NULL DEFAULT 'QUEUED',
    "triggeredById" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "errorMessage" TEXT,
    "discoveredCount" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DiscoveryJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DiscoveredAsset" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "parentAssetId" TEXT NOT NULL,
    "discoveryJobId" TEXT NOT NULL,
    "valueEnc" JSONB NOT NULL,
    "source" TEXT NOT NULL,
    "openPorts" INTEGER[] DEFAULT ARRAY[]::INTEGER[],
    "status" "DiscoveredAssetStatus" NOT NULL DEFAULT 'NEW',
    "promotedAssetId" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DiscoveredAsset_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DiscoveryJob_engagementId_idx" ON "DiscoveryJob"("engagementId");

-- CreateIndex
CREATE INDEX "DiscoveryJob_assetId_idx" ON "DiscoveryJob"("assetId");

-- CreateIndex
CREATE INDEX "DiscoveryJob_status_idx" ON "DiscoveryJob"("status");

-- CreateIndex
CREATE INDEX "DiscoveredAsset_engagementId_idx" ON "DiscoveredAsset"("engagementId");

-- CreateIndex
CREATE INDEX "DiscoveredAsset_parentAssetId_idx" ON "DiscoveredAsset"("parentAssetId");

-- CreateIndex
CREATE INDEX "DiscoveredAsset_status_idx" ON "DiscoveredAsset"("status");

-- AddForeignKey
ALTER TABLE "DiscoveryJob" ADD CONSTRAINT "DiscoveryJob_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveryJob" ADD CONSTRAINT "DiscoveryJob_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredAsset" ADD CONSTRAINT "DiscoveredAsset_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredAsset" ADD CONSTRAINT "DiscoveredAsset_parentAssetId_fkey" FOREIGN KEY ("parentAssetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredAsset" ADD CONSTRAINT "DiscoveredAsset_discoveryJobId_fkey" FOREIGN KEY ("discoveryJobId") REFERENCES "DiscoveryJob"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
