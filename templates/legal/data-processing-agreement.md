> **Not legal advice.** Starting-point template only — have a lawyer licensed
> in your jurisdiction review and adapt before use. Framed around the
> Nigeria Data Protection Act 2023 (NDPA) / NDPR; adapt references and
> obligations to your actual applicable data protection law(s) if operating
> elsewhere or across multiple jurisdictions.

# Data Processing Agreement

This Data Processing Agreement ("**DPA**") is entered into as of
**[Effective Date]** between **[Client Legal Name]** ("**Client**," acting
as Data Controller for its own personal data) and **[Security Firm Legal
Name]** ("**Provider**," acting as Data Processor), and forms part of the
Master Service Agreement between the Parties dated **[date]**.

## 1. Roles

For the purposes of applicable data protection law (including the Nigeria
Data Protection Act 2023 and NDPR), Client is the Data Controller and
Provider is a Data Processor with respect to any personal data Provider
processes in connection with performing the Services. Where testing
incidentally exposes personal data belonging to Client's own customers or
employees (e.g. via a successfully exploited vulnerability revealing a
database of user records), Client remains the Controller for that data;
Provider processes it only as strictly necessary to document and remediate
the finding.

## 2. Scope and purpose of processing

Provider processes personal data solely to perform the Services described
in the applicable Rules of Engagement — specifically: to document security
findings, to demonstrate and reproduce vulnerabilities, and to prepare
reports. Provider will not process personal data for any other purpose.

## 3. Types of data and data subjects

- **Categories of personal data:** [e.g. names, email addresses, credentials
  (hashed or plaintext, if exposed by a finding), IP addresses, any personal
  data incidentally exposed by a vulnerability]
- **Categories of data subjects:** [e.g. Client's employees, Client's
  customers/end users]

## 4. Provider's obligations

Provider will:

- process personal data only on Client's documented instructions (including
  those in the ROE), unless required to do otherwise by law;
- ensure persons authorized to process personal data are bound by
  confidentiality (see the Master Service Agreement, Section 6, and the
  Mutual NDA);
- implement appropriate technical and organizational security measures,
  including — where the assessment platform itself is used to store
  findings/evidence — AES-256-GCM envelope encryption of stored findings and
  evidence at rest, role-based access control, and audit logging of every
  access to sensitive records;
- assist Client, at Client's reasonable request and expense, in responding
  to data subject rights requests and in fulfilling Client's own
  NDPA/NDPR obligations (e.g. Data Protection Impact Assessments);
- notify Client without undue delay, and in any event within
  **[24-48 hours]**, upon becoming aware of a personal data breach affecting
  data processed under this DPA, providing available details so Client can
  meet its own regulatory notification timelines (including the NDPC
  notification window);
- at Client's choice, delete or return all personal data at the end of the
  engagement (see Section 7), except where retention is required by law;
- make available to Client information reasonably necessary to demonstrate
  compliance with this DPA, and allow for audits by Client or its designated
  auditor on reasonable notice.

## 5. Sub-processors

Provider may engage sub-processors (e.g. cloud infrastructure or storage
providers) to perform the Services, provided that:

- Provider maintains a list of current sub-processors and makes it available
  to Client on request — currently: **[e.g. Supabase (database and file
  storage), Vercel (application hosting)]**;
- Provider imposes data protection obligations on each sub-processor no less
  protective than this DPA;
- Provider remains fully liable to Client for each sub-processor's
  performance;
- Client is notified of any intended change of sub-processor and may object
  on reasonable grounds.

## 6. International data transfers

Where personal data is transferred outside **[Nigeria / Client's
jurisdiction]**, Provider will ensure an appropriate transfer mechanism is
in place (e.g. adequacy decision, standard contractual clauses, or another
NDPA-recognized safeguard) before the transfer occurs.

## 7. Retention and deletion

Unless a longer period is required by law or agreed in writing, Provider
will securely delete all personal data processed under this DPA — including
encrypted evidence files and encrypted findings referencing it — no later
than **[90 days]** after the engagement's final report is delivered, and
will confirm deletion to Client in writing upon request.

## 8. Liability

Each Party's liability under this DPA is subject to the limitations set out
in the Master Service Agreement, Section 10, except that nothing in this DPA
limits either Party's liability for a Party's own violations of applicable
data protection law that cannot be limited as a matter of law.

## Signatures

| | Client (Controller) | Provider (Processor) |
|---|---|---|
| Name | | |
| Title | | |
| Signature | | |
| Date | | |
