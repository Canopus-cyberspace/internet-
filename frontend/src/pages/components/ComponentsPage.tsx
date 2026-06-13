import { ComponentCenterView } from "../../features/plugin/components/ComponentCenterView";
import { PageShell } from "../../shared/layout/PageShell";

export function ComponentsPage() {
  return (
    <PageShell title="Components" eyebrow="Plugin catalog">
      <ComponentCenterView />
    </PageShell>
  );
}
