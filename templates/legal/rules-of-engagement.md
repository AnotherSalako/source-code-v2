> **Not legal advice.** Starting-point template only — have a lawyer licensed
> in your jurisdiction review and adapt before use. This document is what
> `authorizationDocRef` on an Engagement should reference, and the platform
> will not allow any test or finding to be created until this is signed and
> on file (see `POST /engagements/:id/authorize`).

# Rules of Engagement / Statement of Work

**Engagement reference:** [Engagement ID / name]
**Governed by:** Master Service Agreement dated [date] between [Provider] and [Client]

This Rules of Engagement ("**ROE**") authorizes Provider to perform the
security testing described below against Client's systems, and defines the
boundaries of that authorization. **Testing outside the scope, dates, or
techniques listed here is not authorized and will not be performed.**

## 1. In-scope systems

| Asset | Type | Identifier (IP/hostname/URL) | Criticality | Notes |
|---|---|---|---|---|
| | | | | |
| | | | | |

## 2. Out-of-scope / explicitly excluded

List anything adjacent that must NOT be touched — third-party services,
production databases, systems outside Client's authority to authorize, etc.

- [e.g. Payment processor (Stripe) — third-party, not authorized]
- [e.g. Production database — read-only observation only, no write/delete testing]
- [ ]

## 3. Testing window

- **Start date:** [date]
- **End date:** [date]
- **Permitted hours:** [e.g. business hours only / 24-7 / outside business hours only to avoid production impact]
- **Time zone:** [timezone]

## 4. Authorized testing types

- [ ] Automated vulnerability scanning
- [ ] Manual web/API application testing
- [ ] Manual mobile application testing
- [ ] Network/infrastructure penetration testing
- [ ] Cloud configuration review
- [ ] Social engineering / phishing simulation (**requires separate explicit written authorization — never assumed**)
- [ ] Physical security testing (**requires separate explicit written authorization — never assumed**)

## 5. Explicitly excluded techniques

Unless individually checked and initialed by Client below, the following
are **not** authorized under this ROE:

- [ ] Denial-of-service or availability-impacting testing
- [ ] Testing against production data with destructive potential (data
      deletion, ransomware simulation, etc.)
- [ ] Social engineering of Client's employees (phishing, pretexting, physical tailgating)
- [ ] Testing outside the systems and window listed in Sections 1 and 3

## 6. Emergency contacts and stop conditions

| Role | Name | Phone | Email |
|---|---|---|---|
| Client technical contact | | | |
| Client emergency/escalation contact | | | |
| Provider lead tester | | | |
| Provider engagement manager | | | |

**Stop conditions:** Testing will pause immediately and Client's emergency
contact will be notified if: (a) unintended production impact occurs, (b)
evidence of an active, unrelated compromise is discovered, or (c) either
Party's designated contact requests a pause.

## 7. Data handling during testing

- Any Client data accessed incidentally during testing (e.g. via a
  successfully exploited vulnerability) will be handled per the Data
  Processing Agreement between the Parties.
- Evidence collected (screenshots, extracted data samples, logs) will be
  limited to what is necessary to demonstrate and remediate the finding, and
  will be stored encrypted at rest for the duration of the engagement plus
  **[retention period, e.g. 90 days]**, then securely deleted.

## 8. Deliverables

- [ ] Executive summary report
- [ ] Technical report (findings, evidence, reproduction steps, remediation guidance)
- [ ] Remediation roadmap (prioritized, with effort estimates)
- [ ] Retest report following remediation
- [ ] Compliance gap summary (framework: [NDPR / ISO 27001 / other])
- [ ] Staff security-awareness training session

## 9. Fees

Per the Master Service Agreement, Section 4, or as follows:
**[amount / payment schedule specific to this engagement, if different]**

## Authorization

By signing below, Client confirms it has the legal right and authority to
authorize testing of every system listed in Section 1, and authorizes
Provider to perform the testing described in this ROE, subject to its
limits.

| | Provider | Client |
|---|---|---|
| Name | | |
| Title | | |
| Signature | | |
| Date | | |
