import { env } from "../config/env";
import { AiTriageProvider } from "./provider";
import { NoopAiTriageProvider } from "./noop";
import { AnthropicAiTriageProvider } from "./providers/anthropic";

// Single shared instance, selected by AI_TRIAGE_PROVIDER — the only place
// in the app that constructs one. Mirrors src/threat-response/index.ts.
function buildAiTriageProvider(): AiTriageProvider {
  if (env.aiTriageProvider === "anthropic") {
    return new AnthropicAiTriageProvider(env.anthropicApiKey!, env.aiTriageModel);
  }
  return new NoopAiTriageProvider();
}

export const aiTriage: AiTriageProvider = buildAiTriageProvider();
export * from "./provider";
