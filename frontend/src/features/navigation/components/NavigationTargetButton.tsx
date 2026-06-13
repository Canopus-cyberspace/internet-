import type {
  NavigationTargetKindDto,
  NavigationViewKindDto,
} from "../../../bridge/dto/navigation";
import { useNavigationStore } from "../../../stores/navigationStore";
import { humanize } from "../../../shared/renderers";

export function NavigationTargetButton({
  label,
  sourceView,
  targetId,
  targetKind,
}: {
  readonly label?: string;
  readonly sourceView: NavigationViewKindDto;
  readonly targetId: string;
  readonly targetKind: NavigationTargetKindDto;
}) {
  const open = useNavigationStore((state) => state.open);
  return (
    <button
      className="graph-node-chip"
      type="button"
      onClick={() =>
        open({
          source_view: sourceView,
          target_kind: targetKind,
          target_id: targetId,
        })
      }
    >
      {label ?? humanize(targetKind)}
    </button>
  );
}

export function NavigationRefButtons({
  refs,
  sourceView,
  targetKind,
}: {
  readonly refs: string[];
  readonly sourceView: NavigationViewKindDto;
  readonly targetKind: NavigationTargetKindDto;
}) {
  if (!refs.length) {
    return null;
  }
  return (
    <div className="graph-node-strip" aria-label={`${humanize(targetKind)} references`}>
      {refs.slice(0, 6).map((targetId, index) => (
        <NavigationTargetButton
          key={`${targetKind}:${targetId}`}
          label={`${humanize(targetKind)} ${index + 1}`}
          sourceView={sourceView}
          targetId={targetId}
          targetKind={targetKind}
        />
      ))}
    </div>
  );
}
