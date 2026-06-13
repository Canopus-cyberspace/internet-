import { renderToStaticMarkup } from "react-dom/server";
import { isValidElement } from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { INITIAL_DETACHED_PANE_STATE, useUiStore } from "../../stores/uiStore";
import { findByClassName } from "../testing/reactElementQueries";
import { BottomGraphPane, BottomGraphPaneHeader } from "./BottomGraphPane";

describe("BottomGraphPane drag-out detach affordance", () => {
  beforeEach(() => {
    useUiStore.setState({
      bottomGraphOpen: true,
      detachedPanes: { ...INITIAL_DETACHED_PANE_STATE },
    });
  });

  it("renders the drag-out header and grip separately from resize splitters", () => {
    const markup = renderToStaticMarkup(<BottomGraphPane />);

    expect(markup).toContain("data-pane-dock-zone=\"true\"");
    expect(markup).toContain("data-drag-out-detach-handle=\"true\"");
    expect(markup).toContain("pane-detach-grip");
    expect(markup).toContain("title=\"Detach graph\"");
    expect(markup).not.toContain("role=\"separator\"");
  });

  it("binds the pointer-down drag handler only to the explicit graph pane grip", () => {
    const onPointerDown = () => undefined;
    const header = BottomGraphPaneHeader({
      dragOutHandleProps: {
        "data-drag-out-detach-handle": "true",
        onPointerDown,
        title: "Drag out to detach pane",
      },
      graphDetached: false,
      onDetachGraph: () => undefined,
    });

    expect(isValidElement(header)).toBe(true);
    expect(header.props.className).toContain("pane-detach-header");
    expect(header.props.onPointerDown).toBeUndefined();
    expect(header.props["data-drag-out-detach-handle"]).toBeUndefined();

    const grip = findByClassName(header, "pane-detach-grip")[0];
    const buttons = findByClassName(header, "icon-button");

    expect(grip.props.onPointerDown).toBe(onPointerDown);
    expect(grip.props["data-drag-out-detach-handle"]).toBe("true");
    expect(buttons).toHaveLength(2);
    expect(buttons.every((button) => button.props.onPointerDown === undefined)).toBe(
      true,
    );
  });
});
