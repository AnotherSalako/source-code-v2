import { logger } from "../../config/logger";
import { AttackPathProvider, PathNarration } from "../attack-path-provider";

const API_URL = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";
const REQUEST_TIMEOUT_MS = 30_000;

const SYSTEM_PROMPT = `You are assisting a human security analyst reviewing structurally-flagged \
pairs of findings: an "entry point" (a HIGH/CRITICAL finding on an internet-facing asset) and a \
"target" (a live finding on a high-criticality asset). These pairs were chosen by deterministic \
rules, not by you — your only job is narrating whether/how the entry point could plausibly lead \
to compromising the target, in 1-3 concrete sentences, and rating how plausible that chain \
actually is. You do not decide anything and this is not proof either finding is real or \
exploitable — a human reviews everything you say.

You will be given a numbered list of pairs. Respond with ONLY a JSON array, no markdown fences, \
no other text, one object per pair using its exact given index:
[{"index": number, "narrative": string, "plausibility": "LOW"|"MEDIUM"|"HIGH"}, ...]

Be honest about weak connections — if a pair doesn't form a coherent story beyond "both exist in \
the same engagement," say so and rate it LOW rather than inventing a chain that isn't there.`;

interface CandidateInput {
  index: number;
  entryTitle: string;
  entrySeverity: string;
  targetTitle: string;
  targetSeverity: string;
  targetCriticality: string;
}

function isPlausibility(v: unknown): v is PathNarration["plausibility"] {
  return v === "LOW" || v === "MEDIUM" || v === "HIGH";
}

export class AnthropicAttackPathProvider implements AttackPathProvider {
  constructor(private readonly apiKey: string, private readonly model: string) {}

  async narratePaths(candidates: CandidateInput[]): Promise<PathNarration[] | null> {
    if (candidates.length === 0) return [];

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const listText = candidates
        .map((c) => `${c.index}. Entry: "${c.entryTitle}" (${c.entrySeverity}) → Target: "${c.targetTitle}" (${c.targetSeverity}, on a ${c.targetCriticality}-criticality asset)`)
        .join("\n");

      const res = await fetch(API_URL, {
        method: "POST",
        signal: controller.signal,
        headers: { "x-api-key": this.apiKey, "anthropic-version": API_VERSION, "content-type": "application/json" },
        body: JSON.stringify({
          model: this.model,
          max_tokens: 1536,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: listText }],
        }),
      });
      if (!res.ok) {
        logger.warn({ status: res.status }, "Attack-path narration request failed");
        return null;
      }
      const body = (await res.json()) as { content?: { type: string; text?: string }[] };
      const text = body.content?.find((block) => block.type === "text")?.text;
      if (!text) return null;

      const stripped = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "");
      let parsed: unknown;
      try {
        parsed = JSON.parse(stripped);
      } catch {
        return null;
      }
      if (!Array.isArray(parsed)) return null;

      // Loose parse here, strict validation in attack-path.service.ts —
      // same two-layer discipline as nl-query.service.ts: this provider
      // only needs to produce *something shaped like* the contract, the
      // caller is what actually enforces index bounds and drops anything
      // malformed before it reaches a response.
      const narrations: PathNarration[] = [];
      for (const item of parsed) {
        if (
          typeof item === "object" &&
          item !== null &&
          typeof (item as any).index === "number" &&
          typeof (item as any).narrative === "string" &&
          isPlausibility((item as any).plausibility)
        ) {
          narrations.push({ index: (item as any).index, narrative: (item as any).narrative, plausibility: (item as any).plausibility });
        }
      }
      return narrations;
    } catch (err) {
      logger.warn({ err }, "Attack-path narration request errored");
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
}
