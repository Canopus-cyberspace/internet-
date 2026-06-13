import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
} from "react";
import {
  invalidateQueriesForEnvelope,
  isCriticalStreamEvent,
  type StreamEventEnvelope,
} from "../../bridge/eventHandlers";
import { registerWindowCloseShutdown } from "../../bridge/lifecycle";
import { subscribeCoreEvents } from "../../bridge/tauri/events";
import { mapCoreError } from "../../bridge/tauri/errors";
import { useNotificationStore } from "../../stores/notificationStore";
import { useStreamStore } from "../../stores/streamStore";

interface TauriEventContextValue {
  connected: boolean;
  ingestEnvelope: (envelope: StreamEventEnvelope) => void;
}

const TauriEventContext = createContext<TauriEventContextValue | undefined>(
  undefined,
);

interface TauriEventProviderProps {
  children: ReactNode;
}

export function TauriEventProvider({ children }: TauriEventProviderProps) {
  const queryClient = useQueryClient();
  const connected = useStreamStore((state) => state.connected);
  const setConnected = useStreamStore((state) => state.setConnected);
  const applyEnvelope = useStreamStore((state) => state.applyEnvelope);
  const incrementStreamBadge = useNotificationStore(
    (state) => state.incrementStreamBadge,
  );
  const pushBanner = useNotificationStore((state) => state.pushBanner);
  const pushToast = useNotificationStore((state) => state.pushToast);

  const ingestEnvelope = useCallback(
    (envelope: StreamEventEnvelope) => {
      applyEnvelope(envelope);
      incrementStreamBadge();
      if (isCriticalStreamEvent(envelope)) {
        pushBanner({
          id: envelope.event_id,
          level: "critical",
          message: envelope.redacted_summary,
        });
      }
      void invalidateQueriesForEnvelope(queryClient, envelope);
    },
    [applyEnvelope, incrementStreamBadge, pushBanner, queryClient],
  );

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | null = null;
    let unlistenClose: (() => void) | null = null;

    setConnected(false);
    void registerWindowCloseShutdown()
      .then((unsubscribe) => {
        if (!active) {
          unsubscribe();
          return;
        }
        unlistenClose = unsubscribe;
      })
      .catch((error: unknown) => {
        const mapped = mapCoreError(error);
        pushToast({
          id: `window-close:${mapped.traceId ?? mapped.code}`,
          level: "warning",
          message: mapped.message,
        });
      });

    void subscribeCoreEvents((envelope) => {
      if (active) {
        ingestEnvelope(envelope);
      }
    })
      .then((unsubscribe) => {
        if (!active) {
          unsubscribe();
          return;
        }
        unlisten = unsubscribe;
        setConnected(true);
      })
      .catch((error: unknown) => {
        const mapped = mapCoreError(error);
        setConnected(false);
        pushToast({
          id: `stream:${mapped.traceId ?? mapped.code}`,
          level: mapped.kind === "service" ? "warning" : "critical",
          message: mapped.message,
        });
      });

    return () => {
      active = false;
      setConnected(false);
      unlisten?.();
      unlistenClose?.();
    };
  }, [ingestEnvelope, pushToast, setConnected]);

  const value = useMemo(
    () => ({ connected, ingestEnvelope }),
    [connected, ingestEnvelope],
  );

  return (
    <TauriEventContext.Provider value={value}>
      {children}
    </TauriEventContext.Provider>
  );
}

export function useTauriEventBridge() {
  const value = useContext(TauriEventContext);
  if (!value) {
    throw new Error("useTauriEventBridge must be used within TauriEventProvider");
  }
  return value;
}
