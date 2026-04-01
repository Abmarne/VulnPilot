import { NextResponse } from "next/server";
import { getScan } from "@/lib/store";

export async function GET(_: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

  return NextResponse.json({
    findings: scan.findings,
    summary: scan.summary,
    status: scan.status
  });
}
