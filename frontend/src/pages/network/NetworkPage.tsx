import { NetworkWorkspace } from "../../features/network/components/NetworkWorkspace";
import { PageShell } from "../../shared/layout/PageShell";

export function NetworkPage() {
  return (
    <PageShell title="Network" eyebrow="Metadata observations">
      <NetworkWorkspace />
    </PageShell>
  );
}
