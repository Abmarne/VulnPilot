import { fetchGitHubRepoSnapshot } from "@/lib/github";
import { analyzeRepository } from "@/lib/scanner";
import { getScan, setScanStatus, updateScan } from "@/lib/store";
import { summarizeFindings } from "@/lib/utils";

export async function runScan(scanId: string) {
  const scan = await getScan(scanId);
  if (!scan) {
    return;
  }

  await setScanStatus(scanId, "analyzing");

  try {
    const snapshot = await fetchGitHubRepoSnapshot(scan.repoUrl, scan.input.branch);
    const result = await analyzeRepository(snapshot, scan.input);

    await updateScan(scanId, {
      status: "report_ready",
      repoName: `${snapshot.repo.owner}/${snapshot.repo.name}`,
      repo: snapshot.repo,
      findings: result.findings,
      summary: summarizeFindings(result.findings),
      frameworks: result.frameworks,
      languages: result.languages,
      notes: result.notes
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected scan failure.";
    await setScanStatus(scanId, "failed", message);
  }
}
