import { GraphWorkspace } from "../../features/graph/components/GraphWorkspace";
import { PageShell } from "../../shared/layout/PageShell";

export function GraphPage() {
  return (
    <PageShell title="Graph" eyebrow="GraphViewModel only">
      <GraphWorkspace />
    </PageShell>
  );
}
