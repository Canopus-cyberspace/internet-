import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useSelectionStore } from "../../stores/selectionStore";
import { INITIAL_DETACHED_PANE_STATE, useUiStore } from "../../stores/uiStore";
import {
  callClick,
  findByClassName,
  textContent,
} from "../testing/reactElementQueries";
import { DetailDrawer, DetailDrawerTabs } from "./DetailDrawer";

describe("DetailDrawer tabs", () => {
  afterEach(() => {
    useUiStore.setState({
      detachedPanes: { ...INITIAL_DETACHED_PANE_STATE },
      detailDrawerOpen: true,
    });
    useSelectionStore.setState({ selectedEntity: null });
  });

  it("keeps Evidence, Timeline, and Response tabs clickable", () => {
    const onSelectTab = vi.fn();
    const tree = DetailDrawerTabs({
      activeTab: "evidence",
      onSelectTab,
    });

    const timelineTab = findByClassName(tree, "drawer-tab").find((element) =>
      textContent(element).includes("Timeline"),
    );
    const responseTab = findByClassName(tree, "drawer-tab").find((element) =>
      textContent(element).includes("Response"),
    );

    expect(timelineTab?.props["aria-selected"]).toBe(false);
    expect(responseTab?.props["aria-selected"]).toBe(false);
    callClick(timelineTab!);
    callClick(responseTab!);

    expect(onSelectTab).toHaveBeenNthCalledWith(1, "timeline");
    expect(onSelectTab).toHaveBeenNthCalledWith(2, "response");
  });

  it("exposes native detach actions for the inspector and active evidence tab", () => {
    useUiStore.setState({
      detachedPanes: { ...INITIAL_DETACHED_PANE_STATE },
      detailDrawerOpen: true,
    });
    useSelectionStore.setState({
      selectedEntity: {
        entityId: "finding:1",
        entityType: "finding",
        fields: {
          Summary: "Redacted metadata finding",
        },
        severity: "high",
        source: "command",
        subtitle: "finding:1",
        title: "Redacted finding",
      },
    });

    const markup = renderToStaticMarkup(<DetailDrawer />);

    expect(markup).toContain("title=\"Detach inspector\"");
    expect(markup).toContain("title=\"Detach active evidence tab\"");
    expect(markup).toContain("No entity selected");
  });
});
