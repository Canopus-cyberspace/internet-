import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it } from "vitest";
import { useNavigationStore } from "../../../stores/navigationStore";
import { NavigationTargetButton } from "./NavigationTargetButton";

describe("bounded navigation context", () => {
  beforeEach(() => {
    useNavigationStore.getState().clear();
  });

  it("renders only a bounded category label and preserves breadcrumb context", () => {
    const markup = renderToStaticMarkup(
      <NavigationTargetButton
        label="Open evidence"
        sourceView="investigation"
        targetId="evidence-safe-ref"
        targetKind="evidence"
      />,
    );

    expect(markup).toContain("Open evidence");
    expect(markup).not.toContain("https://");
    expect(markup).not.toContain("session_token");

    const store = useNavigationStore.getState();
    store.open({
      source_view: "investigation",
      target_kind: "hypothesis",
      target_id: "hypothesis-safe-ref",
    });
    useNavigationStore.getState().open({
      source_view: "investigation",
      target_kind: "evidence",
      target_id: "evidence-safe-ref",
    });

    expect(useNavigationStore.getState().breadcrumbs).toEqual([
      {
        source_view: "investigation",
        target_kind: "hypothesis",
        target_id: "hypothesis-safe-ref",
      },
    ]);
  });
});
