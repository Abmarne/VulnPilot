import { NextResponse } from "next/server";
import { z } from "zod";
import { runScan } from "@/lib/scan-job";
import { createScan, listScans } from "@/lib/store";

const scanInputSchema = z.object({
  repoUrl: z.string().url().max(200),
  branch: z.string().max(80).optional(),
  llm: z
    .object({
      provider: z.string().default("openai-compatible"),
      model: z.string().default("gpt-4.1-mini"),
      apiKey: z.string().optional(),
      baseUrl: z.string().url().optional()
    })
    .optional()
});

export async function GET() {
  const scans = await listScans();
  return NextResponse.json({ scans });
}

export async function POST(request: Request) {
  try {
    const json = await request.json();
    const input = scanInputSchema.parse(json);
    const scan = await createScan(input);

    setTimeout(() => {
      void runScan(scan.id);
    }, 0);

    return NextResponse.json({ scan }, { status: 202 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to create scan.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
