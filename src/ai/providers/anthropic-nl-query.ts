import { logger } from "../../config/logger";
import { NlQueryProvider } from "../query-provider";

const API_URL = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";
const REQUEST_TIMEOUT_MS = 30_000;

// The exact whitelist findings-query.ts's Zod schema enforces — listed here
// too so the model is constrained to fields that actually exist, not
// because this prompt is itself a security boundary (it isn't; the Zod
// validation on the other end is). A model that ignores this and invents a
// field just produces an object findings-query.ts's schema strips or
// rejects, same as any other malformed client input would be.
const SYSTEM_PROMPT = `You translate a security analyst's natural-language question about \
vulnerability findings into a structured JSON filter — you never write a database query \
yourself, only describe constraints for one Jupiter already knows how to run safely.

Respond with ONLY a single JSON object, no markdown fences, no other text. Every field is \
optional — include only the ones the question actually implies. Exact shape:
{
  "severity": ["INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL", ...],
  "status": ["OPEN"|"REMEDIATING"|"RETESTED_PASS"|"RETESTED_FAIL"|"ACCEPTED_RISK", ...],
  "assetType": ["WEB"|"MOBILE"|"SERVER"|"CLOUD"|"NETWORK"|"API", ...],
  "cvssMin": number (0-10),
  "cvssMax": number (0-10),
  "discoveredAfter": "YYYY-MM-DD",
  "discoveredBefore": "YYYY-MM-DD",
  "titleContains": string
}

"Open" or "unresolved" findings means status ["OPEN", "REMEDIATING"]. "Critical" alone with \
no other severity mentioned means severity ["CRITICAL"]. "Last N days" means discoveredAfter \
set to N days before today. If the question doesn't map to any of these fields at all, \
respond with an empty object {}.`;

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

export class AnthropicNlQueryProvider implements NlQueryProvider {
  constructor(private readonly apiKey: string, private readonly model: string) {}

  async translateQuery(question: string): Promise<Record<string, unknown> | null> {
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
          max_tokens: 512,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: `Today's date is ${todayIso()}.\nQuestion: ${question}` }],
        }),
      });
      if (!res.ok) {
        logger.warn({ status: res.status }, "NL query translation request failed");
        return null;
      }
      const body = (await res.json()) as { content?: { type: string; text?: string }[] };
      const text = body.content?.find((block) => block.type === "text")?.text;
      if (!text) return null;

      const stripped = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "");
      try {
        const parsed = JSON.parse(stripped);
        // Only the shape (a plain object) is checked here — every field's
        // actual validity is findings-query.ts's job via Zod, not this
        // provider's. Returning the raw parse keeps that one validation
        // boundary in one place instead of two layers half-checking it.
        return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : null;
      } catch {
        return null;
      }
    } catch (err) {
      logger.warn({ err }, "NL query translation request errored");
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
}
