import { SettingsWorkspace } from "../../features/settings/components/SettingsWorkspace";
import { PageShell } from "../../shared/layout/PageShell";

export function SettingsPage() {
  return (
    <PageShell title="Settings" eyebrow="Operational profile">
      <SettingsWorkspace />
    </PageShell>
  );
}
