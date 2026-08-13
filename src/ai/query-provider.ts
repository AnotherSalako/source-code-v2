/**
 * Swappable AI-assistance boundary, same pattern as AiTriageProvider
 * (provider.ts) — deliberately narrow. This translates a natural-language
 * question into a *structured filter object*, never SQL and never a raw
 * database query of any kind. The provider's output is untrusted input:
 * the caller (findings.routes.ts) validates every field against a strict
 * Zod whitelist before it ever touches a Prisma query, exactly the same
 * way user-supplied JSON would be treated. An AI provider that's been
 * prompt-injected via a crafted finding title, or that just hallucinates a
 * field name, can produce nonsense — it can never produce a query Jupiter
 * didn't already know how to run safely, because it never produces a query
 * at all, only a plain object describing constraints on one.
 */
export interface NlQueryProvider {
  /** Returns a raw, not-yet-validated filter object, or null if no provider is configured or the request failed. */
  translateQuery(question: string): Promise<Record<string, unknown> | null>;
}
