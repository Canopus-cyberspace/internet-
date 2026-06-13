import { InvestigationWorkspace } from "../../features/investigation/components/InvestigationWorkspace";
import { PageShell } from "../../shared/layout/PageShell";

export function InvestigationPage() {
  return (
    <PageShell title="Investigation" eyebrow="Findings, alerts, incidents">
      <InvestigationWorkspace />
    </PageShell>
  );
}
