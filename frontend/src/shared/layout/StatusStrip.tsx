import { useEffect, useState } from "react";
import { statusSlots } from "../../app/navigation";
import type { ServiceStatusViewDto } from "../../bridge/dto/platform";
import { useServiceStatusQuery } from "../../features/platform/hooks";
import { useSelectionStore } from "../../stores/selectionStore";
import { useStreamStore } from "../../stores/streamStore";

type StatusSlot = (typeof statusSlots)[number];

function compactStatus(status: string | undefined) {
  return status ? status.replaceAll("_", " ") : "unknown";
}

function serviceDotClass(
  serviceStatus: ServiceStatusViewDto | undefined,
  streamConnected: boolean,
) {
  if (!serviceStatus) {
    return streamConnected ? "status-dot ok" : "status-dot unknown";
  }
  if (serviceStatus.connected && !serviceStatus.degraded) {
    return "status-dot ok";
  }
  return serviceStatus.degraded ? "status-dot degraded" : "status-dot unknown";
}

export function StatusStrip() {
  const connected = useStreamStore((state) => state.connected);
  const captureStatus = useStreamStore((state) => state.captureStatus);
  const streamServiceStatus = useStreamStore((state) => state.serviceStatus);
  const attributionStatus = useStreamStore((state) => state.attributionStatus);
  const riskStatus = useStreamStore((state) => state.riskStatus);
  const incidentCount = useStreamStore((state) => state.incidentCount);
  const unreadAlertCount = useStreamStore((state) => state.unreadAlertCount);
  const privacyStatus = useStreamStore((state) => state.privacyStatus);
  const activeResponseCount = useStreamStore(
    (state) => state.activeResponseCount,
  );
  const lastPulseAt = useStreamStore((state) => state.lastPulseAt);
  const lastSummary = useStreamStore((state) => state.lastSummaryRedacted);
  const selectedRowCount = useSelectionStore((state) =>
    Object.values(state.tableSelections).reduce(
      (count, selectedRows) => count + selectedRows.length,
      0,
    ),
  );
  const [streamPulse, setStreamPulse] = useState(false);
  const serviceQuery = useServiceStatusQuery();
  const serviceStatus = serviceQuery.data;
  const degraded = Boolean(serviceStatus?.degraded || serviceQuery.isError);
  const serviceText = serviceQuery.isLoading
    ? "checking"
    : serviceQuery.isError
      ? "bridge unavailable"
      : serviceStatus
        ? `${compactStatus(serviceStatus.elevated_service_status)} / core ${compactStatus(
            serviceStatus.local_core_status,
          )} / store ${compactStatus(serviceStatus.storage_status)}`
        : streamServiceStatus;
  const summaryText =
    serviceStatus?.message_redacted ?? lastSummary ?? "Reduced visibility mode";
  const serviceTitle = serviceStatus?.reason
    ? `Service ${compactStatus(serviceStatus.reason)}`
    : serviceStatus?.connected
      ? "Service Online"
      : "Service Offline";
  const statusText: Record<StatusSlot, string> = {
    Capture: captureStatus,
    Service: serviceText,
    Attribution: attributionStatus,
    Risk: riskStatus,
    Incidents: `${incidentCount} / ${unreadAlertCount}`,
    Privacy: privacyStatus,
    "Active Response": String(activeResponseCount),
  };

  useEffect(() => {
    if (!lastPulseAt) {
      return;
    }
    setStreamPulse(true);
    const timeout = window.setTimeout(() => setStreamPulse(false), 1200);
    return () => window.clearTimeout(timeout);
  }, [lastPulseAt]);

  return (
    <footer className="status-strip" data-degraded={degraded ? "true" : "false"}>
      <span
        className={serviceDotClass(serviceStatus, connected)}
        title={serviceTitle}
      />
      <span
        className="stream-activity-dot"
        data-active={streamPulse ? "true" : "false"}
        title="Stream update"
      />
      <span>{connected ? "Event stream connected" : "Event stream idle"}</span>
      {statusSlots.map((slot) => (
        <span key={slot} className="status-chip">
          <strong>{slot}</strong>
          {statusText[slot]}
        </span>
      ))}
      <span className="status-chip">
        <strong>Selected</strong>
        {selectedRowCount}
      </span>
      <span className="status-summary">{summaryText}</span>
    </footer>
  );
}
