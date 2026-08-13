import { env } from "../config/env";
import { ESignatureProvider } from "./provider";
import { NoopESignatureProvider } from "./noop";
import { DocumensoESignatureProvider } from "./providers/documenso";

function buildESignatureProvider(): ESignatureProvider {
  if (env.esignatureProvider === "documenso") {
    return new DocumensoESignatureProvider(env.documensoApiKey!);
  }
  return new NoopESignatureProvider();
}

export const esignature: ESignatureProvider = buildESignatureProvider();
export * from "./provider";
