import { logger } from "../../config/logger";
import { AiTriageProvider, FalsePositiveLikelihood, TriageDraft } from "../provider";

const API_URL = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";
const REQUEST_TIMEOUT_MS = 30_000;

const SYSTEM_PROMPT = `You are assisting a human security analyst who is reviewing a single \
vulnerability finding from a pentest/vuln-scan platform. You do not decide anything — you draft \
a remediation suggestion and flag how likely the finding is to be a false positive, for a human \
to review, edit, or discard. Be concrete: reference specific config changes, headers, code \
patterns, or controls, not generic advice like "follow best practices."

Respond with ONLY a single JSON object, no markdown fences, no other text, in exactly this shape:
{"remediationGuidance": string, "falsePositiveLikelihood": "LOW" | "MEDIUM" | "HIGH", "rationale": string}

"rationale" is 1-3 sentences explaining the false-positive likelihood call specifically — the \
human reviewer sees this alongside the draft, so it needs to justify itself, not just assert it.`;

function parseDraft(text: string): TriageDraft | null {
  // Models occasionally wrap JSON in ```json fences despite instructions —
  // strip them rather than fail a whole triage over formatting.
  const stripped = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "");
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(stripped);
  } catch {
    return null;
  }
  if (typeof parsed.remediationGuidance !== "string" || !parsed.remediationGuidance.trim()) return null;
  const rawLikelihood = typeof parsed.falsePositiveLikelihood === "string" ? parsed.falsePositiveLikelihood.toUpperCase() : "";
  const likelihood: FalsePositiveLikelihood = (["LOW", "MEDIUM", "HIGH"] as const).includes(rawLikelihood as FalsePositiveLikelihood)
    ? (rawLikelihood as FalsePositiveLikelihood)
    : "MEDIUM"; // model returned something unparseable for this field — don't fail the whole draft over it, just don't overclaim confidence
  return {
    remediationGuidance: parsed.remediationGuidance.trim(),
    falsePositiveLikelihood: likelihood,
    rationale: typeof parsed.rationale === "string" ? parsed.rationale.trim() : "",
  };
}

export class AnthropicAiTriageProvider implements AiTriageProvider {
  constructor(private readonly apiKey: string, private readonly model: string) {}

  async draftTriage(input: { title: string; description: string; severity: string }): Promise<TriageDraft | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(API_URL, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "x-api-key": this.apiKey,
          "anthropic-version": API_VERSION,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: 1024,
          system: SYSTEM_PROMPT,
          messages: [
            {
              role: "user",
              content: `Finding title: ${input.title}\nSeverity: ${input.severity}\nDescription:\n${input.description}`,
            },
          ],
        }),
      });
      if (!res.ok) {
        logger.warn({ status: res.status }, "AI triage request failed — finding left without a draft");
        return null;
      }
      const body = (await res.json()) as { content?: { type: string; text?: string }[] };
      const text = body.content?.find((block) => block.type === "text")?.text;
      if (!text) return null;
      return parseDraft(text);
    } catch (err) {
      logger.warn({ err }, "AI triage request errored — finding left without a draft");
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
}
