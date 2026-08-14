import { AwsKmsProvider } from "./providers/aws-kms";

/**
 * GenerateDataKey + Decrypt against the exact key given — proves this
 * credential can actually use *this* key, not just that it authenticates
 * against AWS at all (the same distinction CSPM's verifyCredentials draws
 * against a broader ListBuckets-only check). Separate module from
 * byok.routes.ts so tests can mock this one real network call without
 * needing to mock the AWS SDK client itself.
 */
export async function verifyKmsCredential(params: {
  region: string;
  keyId: string;
  accessKeyId: string;
  secretAccessKey: string;
}): Promise<{ valid: boolean; error?: string }> {
  try {
    const provider = new AwsKmsProvider(params.region, params.keyId, 1, {
      accessKeyId: params.accessKeyId,
      secretAccessKey: params.secretAccessKey,
    });
    const dataKey = await provider.generateDataKey();
    await provider.decryptDataKey(dataKey.encryptedDataKey, params.keyId);
    return { valid: true };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : String(err) };
  }
}
