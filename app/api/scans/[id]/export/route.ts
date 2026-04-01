import { NextResponse } from "next/server";
import { getScan } from "@/lib/store";
import { escapeMarkdown } from "@/lib/utils";

function toMarkdown(scan: NonNullable<Awaited<ReturnType<typeof getScan>>>) {
  const lines = [
    `# VulnPilot report for ${scan.repoName ?? scan.repoUrl}`,
    "",
    `Status: ${scan.status}`,
    `Generated: ${scan.updatedAt}`,
    "",
    "## Summary",
    "",
    `- Total findings: ${scan.summary.total}`,
    `- Critical: ${scan.summary.critical}`,
    `- High: ${scan.summary.high}`,
    `- Medium: ${scan.summary.medium}`,
    `- Low: ${scan.summary.low}`,
    `- Info: ${scan.summary.info}`,
    "",
    "## Findings",
    ""
  ];

  for (const finding of scan.findings) {
    lines.push(`### ${escapeMarkdown(finding.title)}`);
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Confidence: ${finding.confidence}`);
    lines.push(`- Location: ${escapeMarkdown(`${finding.file}:${finding.line}`)}`);
    lines.push(`- Category: ${escapeMarkdown(finding.category)}`);
    lines.push(`- CWE: ${escapeMarkdown(finding.cwe)}`);
    lines.push(`- OWASP: ${escapeMarkdown(finding.owasp)}`);
    if (finding.triageNote) {
      lines.push(`- Review note: ${escapeMarkdown(finding.triageNote)}`);
    }
    lines.push(`- Why it matters: ${escapeMarkdown(finding.whyItMatters)}`);
    lines.push(`- Suggested fix: ${escapeMarkdown(finding.suggestedFix)}`);
    lines.push("");
  }

  return lines.join("\n");
}

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

  const { searchParams } = new URL(request.url);
  const format = searchParams.get("format") ?? "json";

  if (format === "md") {
    return new NextResponse(toMarkdown(scan), {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="${scan.id}.md"`
      }
    });
  }

  return NextResponse.json(scan, {
    headers: {
      "Content-Disposition": `attachment; filename="${scan.id}.json"`
    }
  });
}
