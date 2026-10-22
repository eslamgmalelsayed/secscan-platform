-- CreateEnum
CREATE TYPE "GrantStatus" AS ENUM ('pending_owner', 'active', 'expired', 'revoked');

-- CreateEnum
CREATE TYPE "Environment" AS ENUM ('staging', 'production', 'lab');

-- CreateTable
CREATE TABLE "Grant" (
    "id" TEXT NOT NULL,
    "ownershipProof" TEXT NOT NULL,
    "ownershipToken" TEXT NOT NULL,
    "ownershipVerified" BOOLEAN NOT NULL DEFAULT false,
    "ownershipMethod" TEXT,
    "adminApproved" BOOLEAN NOT NULL DEFAULT false,
    "status" "GrantStatus" NOT NULL DEFAULT 'pending_owner',
    "notBefore" TIMESTAMP(3) NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "allowStateChanging" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Grant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Target" (
    "id" TEXT NOT NULL,
    "position" INTEGER NOT NULL,
    "host" TEXT NOT NULL,
    "scheme" TEXT NOT NULL DEFAULT 'https',
    "port" INTEGER,
    "grantId" TEXT NOT NULL,

    CONSTRAINT "Target_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChainLink" (
    "id" TEXT NOT NULL,
    "position" INTEGER NOT NULL,
    "party" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "statement" TEXT NOT NULL,
    "signedAt" TIMESTAMP(3) NOT NULL,
    "grantId" TEXT NOT NULL,

    CONSTRAINT "ChainLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OwnerChallenge" (
    "id" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "party" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "statement" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "OwnerChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Engagement" (
    "id" TEXT NOT NULL,
    "client" TEXT NOT NULL,
    "preparedBy" TEXT NOT NULL,
    "environment" "Environment" NOT NULL,
    "authorizationRef" TEXT NOT NULL,
    "windowStart" TIMESTAMP(3) NOT NULL,
    "windowEnd" TIMESTAMP(3) NOT NULL,
    "assets" TEXT[],
    "methodologyAr" TEXT NOT NULL,
    "methodologyEn" TEXT NOT NULL,
    "limitationsAr" TEXT NOT NULL,
    "limitationsEn" TEXT NOT NULL,

    CONSTRAINT "Engagement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "notTested" TEXT[],
    "telemetry" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "position" INTEGER NOT NULL,
    "reviewQueue" BOOLEAN NOT NULL DEFAULT false,
    "severity" TEXT NOT NULL,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "confidence" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'open',
    "asset" TEXT NOT NULL,
    "location" TEXT,
    "titleAr" TEXT NOT NULL,
    "titleEn" TEXT NOT NULL,
    "descriptionAr" TEXT NOT NULL,
    "descriptionEn" TEXT NOT NULL,
    "impactAr" TEXT NOT NULL,
    "impactEn" TEXT NOT NULL,
    "remediationAr" TEXT NOT NULL,
    "remediationEn" TEXT NOT NULL,
    "evidence" JSONB NOT NULL,
    "controls" JSONB NOT NULL,
    "retests" JSONB NOT NULL DEFAULT '[]',
    "source" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("scanId","id")
);

-- CreateTable
CREATE TABLE "AuditEntry" (
    "id" TEXT NOT NULL,
    "seq" SERIAL NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actor" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "detail" TEXT,
    "grantId" TEXT,

    CONSTRAINT "AuditEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Target_grantId_position_key" ON "Target"("grantId", "position");

-- CreateIndex
CREATE UNIQUE INDEX "ChainLink_grantId_position_key" ON "ChainLink"("grantId", "position");

-- CreateIndex
CREATE INDEX "OwnerChallenge_grantId_idx" ON "OwnerChallenge"("grantId");

-- CreateIndex
CREATE INDEX "Scan_engagementId_idx" ON "Scan"("engagementId");

-- CreateIndex
CREATE INDEX "AuditEntry_grantId_seq_idx" ON "AuditEntry"("grantId", "seq");

-- AddForeignKey
ALTER TABLE "Target" ADD CONSTRAINT "Target_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "Grant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChainLink" ADD CONSTRAINT "ChainLink_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "Grant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OwnerChallenge" ADD CONSTRAINT "OwnerChallenge_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "Grant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "Grant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEntry" ADD CONSTRAINT "AuditEntry_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "Grant"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Append-only audit log (Design §6): reject UPDATE and DELETE at the database
-- level, so the guarantee does not depend on application code alone.
CREATE OR REPLACE FUNCTION audit_entry_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'AuditEntry is append-only (% rejected)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_entry_no_update BEFORE UPDATE ON "AuditEntry"
  FOR EACH ROW EXECUTE FUNCTION audit_entry_append_only();
CREATE TRIGGER audit_entry_no_delete BEFORE DELETE ON "AuditEntry"
  FOR EACH ROW EXECUTE FUNCTION audit_entry_append_only();
