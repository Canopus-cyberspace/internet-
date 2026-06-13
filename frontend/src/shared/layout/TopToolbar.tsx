import {
  Bell,
  CirclePause,
  Clock3,
  FileText,
  GitBranch,
  Monitor,
  PanelRightClose,
  PanelRightOpen,
  PlayCircle,
  RefreshCw,
  Search,
  Upload,
} from "lucide-react";
import { useTheme } from "../../app/providers/ThemeProvider";
import { useRunDemoStoryMutation } from "../../features/demo/hooks";
import { useNotificationStore } from "../../stores/notificationStore";
import { useStreamStore } from "../../stores/streamStore";
import { useUiStore } from "../../stores/uiStore";

export function TopToolbar() {
  const { theme, setTheme } = useTheme();
  const demoStoryMutation = useRunDemoStoryMutation();
  const bottomGraphOpen = useUiStore((state) => state.bottomGraphOpen);
  const detailDrawerOpen = useUiStore((state) => state.detailDrawerOpen);
  const unreadAlertCount = useStreamStore((state) => state.unreadAlertCount);
  const streamBadgeCount = useNotificationStore((state) => state.streamBadgeCount);
  const resetStreamBadge = useNotificationStore((state) => state.resetStreamBadge);
  const setBottomGraphOpen = useUiStore((state) => state.setBottomGraphOpen);
  const setDetailDrawerOpen = useUiStore(
    (state) => state.setDetailDrawerOpen,
  );
  const notificationCount = Math.min(99, unreadAlertCount + streamBadgeCount);

  return (
    <header className="top-toolbar">
      <div className="toolbar-brand">
        <span className="brand-mark" aria-hidden="true" />
        <div>
          <strong>Sentinel Guard</strong>
          <span>Local Host</span>
        </div>
      </div>
      <div className="toolbar-control">
        <Monitor size={15} aria-hidden="true" />
        <label htmlFor="scope-select">Scope</label>
        <select id="scope-select" defaultValue="local-host">
          <option value="local-host">Local Host</option>
          <option value="process">Process</option>
          <option value="incident">Incident</option>
          <option value="plugin">Plugin</option>
          <option value="capability">Capability</option>
        </select>
      </div>
      <div className="toolbar-control">
        <Clock3 size={15} aria-hidden="true" />
        <label htmlFor="time-select">Time</label>
        <select id="time-select" defaultValue="24h">
          <option value="15m">Last 15m</option>
          <option value="1h">Last 1h</option>
          <option value="24h">Last 24h</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div className="toolbar-actions" aria-label="Toolbar actions">
        <button type="button" className="icon-button" title="Refresh">
          <RefreshCw size={15} aria-hidden="true" />
        </button>
        <button type="button" className="icon-button" title="Search">
          <Search size={15} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="icon-button notification-button"
          title="Notifications"
          onClick={resetStreamBadge}
        >
          <Bell size={15} aria-hidden="true" />
          {notificationCount ? (
            <span className="notification-badge">{notificationCount}</span>
          ) : null}
        </button>
        <button
          type="button"
          className="icon-button"
          aria-pressed={bottomGraphOpen}
          title={bottomGraphOpen ? "Hide graph pane" : "Show graph pane"}
          onClick={() => setBottomGraphOpen(!bottomGraphOpen)}
        >
          <GitBranch size={15} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="icon-button"
          aria-pressed={detailDrawerOpen}
          title={detailDrawerOpen ? "Hide detail drawer" : "Show detail drawer"}
          onClick={() => setDetailDrawerOpen(!detailDrawerOpen)}
        >
          {detailDrawerOpen ? (
            <PanelRightClose size={15} aria-hidden="true" />
          ) : (
            <PanelRightOpen size={15} aria-hidden="true" />
          )}
        </button>
        <button type="button" className="toolbar-button" disabled>
          <CirclePause size={15} aria-hidden="true" />
          Observe
        </button>
        <button type="button" className="toolbar-button" disabled>
          <Upload size={15} aria-hidden="true" />
          Import
        </button>
        <button
          type="button"
          className={
            demoStoryMutation.isPending
              ? "toolbar-button is-loading"
              : "toolbar-button"
          }
          disabled={demoStoryMutation.isPending}
          title="Run safe demo story"
          onClick={() => demoStoryMutation.mutate()}
        >
          <PlayCircle size={15} aria-hidden="true" />
          {demoStoryMutation.isPending ? "Running" : "Demo"}
        </button>
        <button type="button" className="toolbar-button" disabled>
          <FileText size={15} aria-hidden="true" />
          Report
        </button>
      </div>
      <div className="toolbar-spacer" />
      <div className="toolbar-control">
        <label htmlFor="theme-select">Theme</label>
        <select
          id="theme-select"
          value={theme}
          onChange={(event) =>
            setTheme(event.currentTarget.value as "system" | "light" | "dark" | "deep-dark")
          }
        >
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
          <option value="deep-dark">Deep Dark</option>
        </select>
      </div>
    </header>
  );
}
