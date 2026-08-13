import { env } from "../config/env";
import { LocalKmsProvider, KmsProvider } from "./kms";
import { AwsKmsProvider } from "./providers/aws-kms";
import { LocalObjectStorage, ObjectStorage } from "./storage";
import { SupabaseObjectStorage } from "./providers/supabase-storage";

// Single shared instances, selected by KMS_PROVIDER — this is the ONLY place
// in the app that constructs a KMS or storage client directly. Live-verified
// against a real AWS account: DescribeKey/GenerateDataKey/Decrypt all
// succeed with the scoped IAM + key-policy grants documented in
// providers/aws-kms.ts, and encryptField/decryptField round-trip correctly
// through the real key. Requires both an IAM identity policy AND the key's
// own resource policy to grant the principal access — missing either one
// produces AccessDeniedException even though the other looks fine.
function buildKmsProvider(): KmsProvider {
  if (env.kmsProvider === "aws") {
    const staticCredentials =
      env.awsKmsStaticAccessKeyId && env.awsKmsStaticSecretAccessKey
        ? { accessKeyId: env.awsKmsStaticAccessKeyId, secretAccessKey: env.awsKmsStaticSecretAccessKey }
        : undefined;
    // AWS_REGION is one of the reserved names too (see aws-kms.ts) — prefer
    // the non-reserved override whenever static credentials are in play.
    const region = env.awsKmsStaticRegion ?? env.awsRegion!;
    return new AwsKmsProvider(region, env.awsKmsKeyId!, env.awsKmsKeyVersion, staticCredentials);
  }
  return new LocalKmsProvider(env.cmkBase64!, env.cmkId, env.cmkVersion);
}

export const kms: KmsProvider = buildKmsProvider();

function buildObjectStorage(): ObjectStorage {
  if (env.storageBackend === "local") {
    return new LocalObjectStorage(env.storageDir);
  }
  if (!env.supabaseUrl || !env.supabaseServiceRoleKey) {
    throw new Error(
      "STORAGE_BACKEND=supabase requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY " +
        "(set STORAGE_BACKEND=local for offline dev instead)."
    );
  }
  return new SupabaseObjectStorage(env.supabaseUrl, env.supabaseServiceRoleKey, env.supabaseStorageBucket);
}

export const objectStorage: ObjectStorage = buildObjectStorage();

export * from "./envelope";
export * from "./kms";
export * from "./storage";
