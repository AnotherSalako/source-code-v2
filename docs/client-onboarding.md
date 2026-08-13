# Welcome to Enforcer

This is a short guide for your team — what Enforcer is, what you'll see
when you log in, and who on your side should be looking at what. It's not
a technical manual; it's meant to be handed to whoever on the client side
will actually use the platform.

## What Enforcer is

Enforcer is where your security assessment lives while it's happening —
not a report you get once at the end, but a live system you can check in
on at any point: what's been tested, what's been found, what's being
fixed, and where things stand right now.

## Signing in

You'll receive an email invitation to create an account. Sign in with the
email address it was sent to — that's what ties your account to your
organization's engagement. If you use two-factor authentication elsewhere,
you can turn it on for your account too (under your profile menu).

If you ever see "this account isn't set up yet" after signing in, it means
your account exists but hasn't been linked to your organization on our
side — contact your point of contact and we'll fix it, usually within
minutes.

## Who sees what

Enforcer has two kinds of accounts on the client side, and what you see
depends on which one you have:

- **Executive** — a business-level view. You'll see the overall status of
  the engagement, a plain-language risk summary, compliance standing, and
  the executive report once it's ready. You won't see raw technical
  detail, screenshots, or attack reproduction steps — that's intentional,
  so this view stays a quick, useful check-in rather than something you
  have to wade through.
- **Technical** — full detail. Everything the executive view shows, plus
  the complete findings list, evidence, reproduction steps, and remediation
  guidance your engineering team will actually need to act on.

If you're not sure which one you have, or need someone added, tell your
point of contact — we manage account provisioning on our side.

## Finding your way around

Once you're in an engagement, here's what each section is:

- **Overview** — start here. Shows the engagement's current stage
  (Scoping → Authorized → Testing → Findings identified → Remediation →
  Retested → Report delivered) so you can tell at a glance where things
  stand, plus the signed scope and authorization on file.
- **Findings** *(technical accounts)* — every issue identified, with
  severity, status, and full detail.
- **Roadmap** — open findings organized by priority: quick wins you can
  knock out fast, versus longer-term projects. This is meant to be a
  practical to-do list for your team, not just a dump of raw findings.
- **Compliance** — if your engagement includes a compliance review (ISO
  27001, NDPR), this shows where you stand against each control.
- **Training** — any security-awareness sessions scheduled or completed
  as part of the engagement.
- **Reports** — generated executive/technical reports, available to
  download once issued.

On the client organization page (one level up from a specific engagement),
you'll also find a **findings trend** view if you've had more than one
engagement with us — this is where you can see whether risk is trending
down over time, and flag anything that's shown up again in a later
assessment without actually being fixed.

## A few things worth knowing

- **Nothing happens without your authorization on file.** We can't run any
  test or log any finding against your systems until the engagement's
  Rules of Engagement is signed and recorded — you'll see this reflected
  as the "Authorized" stage on the Overview page.
- **Automated scans are still reviewed by a person before anything reaches
  you.** If part of your engagement includes automated scanning, results
  land in our dashboard for our team to review — nothing gets surfaced to
  you as a finding, and nothing goes into a report, without a human
  looking at it first.
- **Everything here is encrypted.** Findings, evidence files, and reports
  are all encrypted at rest — this isn't "stored on an encrypted disk," it's
  encrypted per record, with access logged every time someone views it.

## Questions

If anything here doesn't match what you're seeing, or you're not sure what
something means, reach out to your point of contact directly rather than
guessing — that's faster for everyone than digging through a dashboard
looking for an answer that might not be there yet.
