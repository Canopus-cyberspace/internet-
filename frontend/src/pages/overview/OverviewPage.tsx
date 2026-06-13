import { EmptyState } from "../../shared/layout/EmptyState";
import { PageShell } from "../../shared/layout/PageShell";
import { SplitPane } from "../../shared/layout/SplitPane";
import { ShellTable } from "../../shared/table/ShellTable";

export function OverviewPage() {
  return (
    <PageShell title="Overview" eyebrow="Local security posture">
      <SplitPane
        primary={
          <ShellTable
            columns={[
              { key: "signal", label: "Signal" },
              { key: "risk", label: "Risk" },
              { key: "state", label: "State" },
              { key: "source", label: "Source" },
            ]}
            rows={[
              {
                id: "risk-map",
                severity: "high",
                cells: {
                  signal: "C2-like cadence",
                  risk: "High",
                  state: "Finding",
                  source: "Metadata flow",
                },
              },
              {
                id: "exfil",
                severity: "medium",
                cells: {
                  signal: "Cloud upload drift",
                  risk: "Medium",
                  state: "Observation",
                  source: "DNS/TLS",
                },
              },
              {
                id: "response",
                severity: "low",
                cells: {
                  signal: "Recommended action",
                  risk: "Review",
                  state: "Disabled",
                  source: "Planner",
                },
              },
            ]}
          />
        }
        secondary={
          <EmptyState
            title="Active cases"
            detail="Incident summaries will appear after the risk stage promotes alerts."
          />
        }
      />
    </PageShell>
  );
}
