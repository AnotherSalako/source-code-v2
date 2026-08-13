# Legal templates

Four starting-point documents for running assessment engagements:

- `master-service-agreement.md` — the umbrella contract governing the overall relationship with a client (signed once, covers all future engagements)
- `rules-of-engagement.md` — the per-engagement document: exact scope, authorized dates, excluded techniques, emergency contacts. This is what `authorizationDocRef` on an `Engagement` should point to (see `engagements.routes.ts` — no `Test`/`Finding` can be created until this is on file)
- `nda.md` — mutual non-disclosure agreement
- `data-processing-agreement.md` — covers the firm's own handling of the client's (and their data subjects') data during an engagement, framed around NDPA/NDPR-style obligations

## Important

**These are not legal advice and are not a substitute for a lawyer.** They're
structurally reasonable starting points — the sections a real security
services contract needs — not vetted, jurisdiction-specific legal documents.
Before using any of these with a real client:

- Have them reviewed and adapted by a lawyer licensed in your jurisdiction
- Fill in every `[bracketed placeholder]`
- Confirm the liability caps, indemnification terms, and governing law
  actually match what you and your insurer are comfortable with
- Don't run a real engagement against a real client's systems without a
  signed Rules of Engagement on file — the platform enforces this in code
  (see `POST /engagements/:id/authorize` and the hard gate in
  `tests.routes.ts`), but the document itself has to actually exist and be signed
