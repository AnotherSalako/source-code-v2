-- CreateEnum
CREATE TYPE "UsageEventKind" AS ENUM ('SCAN', 'DISCOVERY', 'AGENT_CHECK_IN');

-- CreateTable
CREATE TABLE "UsageEvent" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "kind" "UsageEventKind" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UsageEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "UsageEvent_clientId_kind_createdAt_idx" ON "UsageEvent"("clientId", "kind", "createdAt");

-- AddForeignKey
ALTER TABLE "UsageEvent" ADD CONSTRAINT "UsageEvent_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
