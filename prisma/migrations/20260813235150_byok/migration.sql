-- CreateTable
CREATE TABLE "ClientKmsCredential" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "region" TEXT NOT NULL,
    "accessKeyIdEnc" JSONB NOT NULL,
    "secretAccessKeyEnc" JSONB NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ClientKmsCredential_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ClientKmsCredential_clientId_key" ON "ClientKmsCredential"("clientId");

-- AddForeignKey
ALTER TABLE "ClientKmsCredential" ADD CONSTRAINT "ClientKmsCredential_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
