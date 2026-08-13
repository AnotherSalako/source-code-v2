import { env } from "../config/env";
import { AiTriageProvider } from "./provider";
import { NlQueryProvider } from "./query-provider";
import { AttackPathProvider } from "./attack-path-provider";
import { NoopAiTriageProvider, NoopNlQueryProvider, NoopAttackPathProvider } from "./noop";
import { AnthropicAiTriageProvider } from "./providers/anthropic";
import { AnthropicNlQueryProvider } from "./providers/anthropic-nl-query";
import { AnthropicAttackPathProvider } from "./providers/anthropic-attack-path";

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

function buildAttackPathProvider(): AttackPathProvider {
  if (env.aiTriageProvider === "anthropic") {
    return new AnthropicAttackPathProvider(env.anthropicApiKey!, env.aiTriageModel);
  }
  return new NoopAttackPathProvider();
}

export const aiTriage: AiTriageProvider = buildAiTriageProvider();
export const nlQuery: NlQueryProvider = buildNlQueryProvider();
export const attackPathAi: AttackPathProvider = buildAttackPathProvider();
export * from "./provider";
export * from "./query-provider";
export * from "./attack-path-provider";
