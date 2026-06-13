import { ResponseWorkspace } from "../../features/response/components/ResponseWorkspace";
import { PageShell } from "../../shared/layout/PageShell";

export function ResponsePage() {
  return (
    <PageShell title="Response" eyebrow="Recommend-first planning">
      <ResponseWorkspace />
    </PageShell>
  );
}
