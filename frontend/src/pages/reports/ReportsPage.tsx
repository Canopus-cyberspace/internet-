import { ReportsWorkspace } from "../../features/report/components/ReportsWorkspace";
import { PageShell } from "../../shared/layout/PageShell";

export function ReportsPage() {
  return (
    <PageShell title="Reports" eyebrow="Redacted exports">
      <ReportsWorkspace />
    </PageShell>
  );
}
