// Real, installed KMS provider — selected via KMS_PROVIDER=aws (see
// src/crypto/index.ts, the only place that constructs it). Live-verified
// against a real AWS account and migrated real data through it.
//
// Required IAM permissions for the app's execution role, scoped to one key ARN:
//   kms:GenerateDataKey
//   kms:Decrypt
// Nothing else — the role must never get kms:GetKeyPolicy, kms:ScheduleKeyDeletion,
// kms:CreateKey, etc. Enable CMK auto-rotation (kms:EnableKeyRotation) in
// infrastructure config, not application code.
//
// staticCredentials is optional and only needed on platforms where the AWS
// SDK's default credential chain can't be trusted — concretely, Vercel (and
// AWS Lambda generally, which Vercel Functions run on) *reserves* the names
// AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_REGION for the execution
// sandbox's own role and silently shadows any user-supplied value of the
// same name at runtime — confirmed live: setting those exact names on Vercel
// saved fine but every KMS call then failed with AccessDenied, because the
// SDK's default chain was picking up Vercel's own unrelated Lambda role, not
// ours. On EC2 (or anywhere else with a real IAM instance role and no
// reserved-name conflict), omit staticCredentials entirely and the default
// chain picks up the instance role correctly, same as always.

import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from "@aws-sdk/client-kms";
import { DataKeyResult, KmsProvider } from "../kms";

export class AwsKmsProvider implements KmsProvider {
  private readonly client: KMSClient;
  private readonly keyId: string;
  private readonly keyVersion: number;

  constructor(region: string, keyId: string, keyVersion: number, staticCredentials?: { accessKeyId: string; secretAccessKey: string }) {
    this.client = new KMSClient({ region, ...(staticCredentials ? { credentials: staticCredentials } : {}) });
    this.keyId = keyId;
    this.keyVersion = keyVersion;
  }

  currentKeyId(): string {
    return this.keyId;
  }

  currentKeyVersion(): number {
    return this.keyVersion;
  }

  async generateDataKey(keyId?: string): Promise<DataKeyResult> {
    // Per-tenant keys (src/crypto/tenant.ts) pass a specific key ARN/alias
    // here — a real, separately-provisioned AWS KMS key, not something this
    // app ever creates itself (see the IAM note at the top of this file:
    // the execution role gets GenerateDataKey/Decrypt only, never
    // CreateKey). Provisioning a tenant's dedicated key is infra work
    // (Terraform/console), done once per client before assigning it via
    // PATCH /clients/:id/kms-key.
    const targetKeyId = keyId ?? this.keyId;
    const res = await this.client.send(
      new GenerateDataKeyCommand({ KeyId: targetKeyId, KeySpec: "AES_256" })
    );
    if (!res.Plaintext || !res.CiphertextBlob) {
      throw new Error("KMS GenerateDataKey returned no key material");
    }
    return {
      plaintextKey: Buffer.from(res.Plaintext),
      encryptedDataKey: Buffer.from(res.CiphertextBlob),
      keyId: targetKeyId,
      keyVersion: this.keyVersion,
    };
  }

  async decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer> {
    const res = await this.client.send(
      new DecryptCommand({ CiphertextBlob: encryptedDataKey, KeyId: keyId })
    );
    if (!res.Plaintext) throw new Error("KMS Decrypt returned no key material");
    return Buffer.from(res.Plaintext);
  }
}
