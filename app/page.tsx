import { Dashboard } from "@/components/dashboard";
import { listScans } from "@/lib/store";

export default async function HomePage() {
  const scans = await listScans();
  return <Dashboard initialScans={scans} />;
}
