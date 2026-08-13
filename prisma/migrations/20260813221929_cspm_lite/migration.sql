-- CreateTable
CREATE TABLE "CloudCredential" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "provider" TEXT NOT NULL DEFAULT 'aws',
    "accessKeyIdEnc" JSONB NOT NULL,
    "secretAccessKeyEnc" JSONB NOT NULL,
    "region" TEXT NOT NULL,
    "lastScannedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudCredential_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CloudCredential_clientId_key" ON "CloudCredential"("clientId");

-- AddForeignKey
ALTER TABLE "CloudCredential" ADD CONSTRAINT "CloudCredential_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
