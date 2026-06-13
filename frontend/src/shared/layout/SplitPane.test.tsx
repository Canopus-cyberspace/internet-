import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PANE_SIZE_LIMITS } from "./paneSizing";
import { SplitPane } from "./SplitPane";

describe("SplitPane", () => {
  it("renders scrollable panes and an accessible resize handle", () => {
    const markup = renderToStaticMarkup(
      <SplitPane primary={<div>Primary</div>} secondary={<div>Secondary</div>} />,
    );

    expect(markup).toContain("split-primary scroll-region");
    expect(markup).toContain("split-secondary scroll-region");
    expect(markup).toContain("role=\"separator\"");
    expect(markup).toContain("aria-orientation=\"vertical\"");
    expect(markup).toContain(`aria-valuemin="${PANE_SIZE_LIMITS.splitSecondary.min}"`);
    expect(markup).toContain(`aria-valuemax="${PANE_SIZE_LIMITS.splitSecondary.max}"`);
    expect(markup).toContain(
      `aria-valuenow="${PANE_SIZE_LIMITS.splitSecondary.defaultSize}"`,
    );
    expect(markup).not.toContain("data-drag-out-detach-handle");
  });
});
