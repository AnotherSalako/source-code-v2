import { env } from "../config/env";
import { AiTriageProvider } from "./provider";
import { NlQueryProvider } from "./query-provider";
import { NoopAiTriageProvider, NoopNlQueryProvider } from "./noop";
import { AnthropicAiTriageProvider } from "./providers/anthropic";
import { AnthropicNlQueryProvider } from "./providers/anthropic-nl-query";

// Single shared instances, selected by AI_TRIAGE_PROVIDER — the only place
// in the app that constructs these. Mirrors src/threat-response/index.ts.
// NL querying reuses the same provider toggle/credentials as triage rather
// than a second env var: it's the same underlying Anthropic account, just a
// different prompt/task, and a separate ENABLE flag would just be one more
// way for the two to silently drift out of sync with each other.
function buildAiTriageProvider(): AiTriageProvider {
  if (env.aiTriageProvider === "anthropic") {
    return new AnthropicAiTriageProvider(env.anthropicApiKey!, env.aiTriageModel);
  }
  return new NoopAiTriageProvider();
}

function buildNlQueryProvider(): NlQueryProvider {
  if (env.aiTriageProvider === "anthropic") {
    return new AnthropicNlQueryProvider(env.anthropicApiKey!, env.aiTriageModel);
  }
  return new NoopNlQueryProvider();
}

export const aiTriage: AiTriageProvider = buildAiTriageProvider();
export const nlQuery: NlQueryProvider = buildNlQueryProvider();
export * from "./provider";
export * from "./query-provider";
