import { FileSearch, type LucideIcon } from "lucide-react";
import { type ReactNode } from "react";
import { useInteractionStates } from "../useInteractionStates";

interface EmptyStateProps {
  action?: ReactNode;
  description?: string;
  title: string;
  detail?: string;
  icon?: LucideIcon;
  tone?: "empty" | "degraded" | "error";
}

export function EmptyState({
  action,
  description,
  title,
  detail,
  icon: Icon = FileSearch,
  tone = "empty",
}: EmptyStateProps) {
  const className = useInteractionStates("empty-state", {
    degraded: tone === "degraded",
    empty: tone === "empty",
    error: tone === "error",
  });
  const text = description ?? detail ?? "No metadata available.";

  return (
    <div className={className}>
      <Icon size={32} aria-hidden="true" />
      <strong>{title}</strong>
      <span>{text}</span>
      {action ? <div className="empty-state-action">{action}</div> : null}
    </div>
  );
}
