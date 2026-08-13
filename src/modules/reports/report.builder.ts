import { PrismaClient, ReportType } from "@prisma/client";
import PDFDocument from "pdfkit";
import { kms } from "../../crypto";
import { decryptField } from "../../crypto/envelope";

/**
 * Renders a report to PDF bytes. The rendering step is fully swappable
 * (Handlebars+Puppeteer, a hosted template service, etc.) — what must not
 * change is that the returned buffer is plaintext in memory only until the
 * caller immediately encrypts it before it touches disk or object storage.
 */
export async function buildReportContent(
  prisma: PrismaClient,
  engagementId: string,
  type: ReportType
): Promise<Buffer> {
  const engagement = await prisma.engagement.findUniqueOrThrow({
    where: { id: engagementId },
    include: { client: true },
  });

  const findings = await prisma.finding.findMany({
    where: { test: { engagementId } },
    orderBy: { severity: "desc" },
  });

  const doc = new PDFDocument({ margin: 50 });
  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve) => doc.on("end", () => resolve(Buffer.concat(chunks))));

  if (type === "EXECUTIVE") {
    const bySeverity = findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {});

    doc.fontSize(20).text("Executive Summary", { underline: true });
    doc.moveDown();
    doc.fontSize(11);
    doc.text(`Client: ${engagement.client.name}`);
    doc.text(`Engagement: ${engagement.id}`);
    doc.text(`Generated: ${new Date().toISOString()}`);
    doc.moveDown();
    doc.fontSize(14).text("Findings by severity");
    doc.fontSize(11);
    for (const [sev, count] of Object.entries(bySeverity)) {
      doc.text(`  ${sev}: ${count}`);
    }
    doc.moveDown();
    doc.text(
      `This assessment identified ${findings.length} issue(s) across in-scope systems. ` +
        `See the accompanying technical report for reproduction steps and remediation guidance.`
    );
  } else {
    // TECHNICAL / RETEST_ADDENDUM: full detail, decrypted only for embedding into this PDF buffer.
    doc.fontSize(20).text("Technical Report", { underline: true });
    doc.moveDown();
    doc.fontSize(11);
    doc.text(`Client: ${engagement.client.name}`);
    doc.text(`Engagement: ${engagement.id}`);
    doc.moveDown();

    for (const f of findings) {
      const description = await decryptField(kms, f.descriptionEnc as any, `finding:description`);
      const repro = f.reproductionStepsEnc
        ? await decryptField(kms, f.reproductionStepsEnc as any, `finding:reproductionSteps`)
        : "N/A";
      const remediation = f.remediationGuidanceEnc
        ? await decryptField(kms, f.remediationGuidanceEnc as any, `finding:remediationGuidance`)
        : "N/A";

      doc.fontSize(13).text(`[${f.severity}] ${f.title} — ${f.status}`, { underline: true });
      doc.fontSize(11);
      doc.text(`Description: ${description}`);
      doc.text(`Reproduction steps: ${repro}`);
      doc.text(`Remediation: ${remediation}`);
      doc.moveDown();
    }
  }

  doc.end();
  return done;
}
