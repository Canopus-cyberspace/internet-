import { ArrowLeft, Link2, ShieldAlert, X } from "lucide-react";
import type { NavigationResolveRequestDto } from "../../../bridge/dto/navigation";
import { useServiceStatusQuery } from "../../platform/hooks";
import { useNavigationStore } from "../../../stores/navigationStore";
import { humanize } from "../../../shared/renderers";
import { useNavigationResolutionQuery } from "../hooks";

export function NavigationContextPanel() {
  const current = useNavigationStore((state) => state.current);
  const breadcrumbs = useNavigationStore((state) => state.breadcrumbs);
  const back = useNavigationStore((state) => state.back);
  const clear = useNavigationStore((state) => state.clear);
  const open = useNavigationStore((state) => state.open);
  const service = useServiceStatusQuery();
  const request: NavigationResolveRequestDto | null = current
    ? {
        ...current,
        session_id: service.data?.active_session_id ?? null,
      }
    : null;
  const resolution = useNavigationResolutionQuery(request);

  if (!current) {
    return null;
  }

  return (
    <section className="analysis-panel navigation-context-panel">
      <div className="analysis-panel-header">
        <strong>Bounded reference navigation</strong>
        <span>
          <Link2 size={14} aria-hidden="true" /> {humanize(current.target_kind)}
        </span>
      </div>
      <div className="graph-node-strip" aria-label="Bounded navigation breadcrumbs">
        {breadcrumbs.length ? (
          <button className="graph-node-chip" type="button" onClick={back}>
            <ArrowLeft size={13} aria-hidden="true" /> Back
          </button>
        ) : null}
        <button className="graph-node-chip" type="button" onClick={clear}>
          <X size={13} aria-hidden="true" /> Close
        </button>
        {breadcrumbs.slice(-4).map((crumb, index) => (
          <span className="analysis-muted" key={`${crumb.target_kind}:${crumb.target_id}:${index}`}>
            {humanize(crumb.target_kind)}
          </span>
        ))}
      </div>
      {resolution.isError ? (
        <div className="response-callout" data-tone="warning">
          <ShieldAlert size={15} aria-hidden="true" />
          <span>Reference was rejected by the session-scoped safety resolver.</span>
        </div>
      ) : resolution.data ? (
        <>
          <div className="metadata-watch-source-row">
            <strong>{humanize(resolution.data.target.category)}</strong>
            <small>
              {humanize(resolution.data.status)} /{" "}
              {humanize(resolution.data.target.confidence_bucket ?? "unknown")} confidence
            </small>
            <small>{humanize(resolution.data.target.redacted_summary)}</small>
            {resolution.data.target.degraded_reason ? (
              <small>Degraded: {humanize(resolution.data.target.degraded_reason)}</small>
            ) : null}
            {resolution.data.target.missing_visibility_flags.length ? (
              <small>
                Missing visibility:{" "}
                {resolution.data.target.missing_visibility_flags
                  .slice(0, 4)
                  .map(humanize)
                  .join(", ")}
              </small>
            ) : null}
          </div>
          <div className="graph-node-strip" aria-label="Related bounded references">
            {resolution.data.outgoing_refs.slice(0, 12).map((reference) => (
              <button
                className="graph-node-chip"
                key={reference.ref_id}
                type="button"
                onClick={() =>
                  open({
                    source_view: reference.source_view,
                    target_kind: reference.target_kind,
                    target_id: reference.target_id,
                  })
                }
              >
                {humanize(reference.target_kind)}
              </button>
            ))}
          </div>
          <div className="response-callout" data-tone="ok">
            <span>
              Session-scoped, metadata-only, no-retention summary. Navigation never triggers
              ingest, exports, reports, LLM calls, native collection, or responses.
            </span>
          </div>
        </>
      ) : (
        <span className="analysis-muted">Resolving bounded reference.</span>
      )}
    </section>
  );
}
