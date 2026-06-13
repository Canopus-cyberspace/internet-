import { describe, expect, it } from "vitest";
import { graphViews, navigationItems, routeTitles, statusSlots } from "./navigation";

describe("app shell navigation", () => {
  it("exposes the eight Task 230 workspace routes in navigation order", () => {
    const paths = navigationItems.map((item) => item.to);
    const labels = navigationItems.map((item) => item.label);

    expect(paths).toEqual([
      "/",
      "/investigation",
      "/graph",
      "/components",
      "/network",
      "/response",
      "/reports",
      "/settings",
    ]);
    expect(labels).toEqual([
      "Overview",
      "Investigation",
      "Graph",
      "Components",
      "Network",
      "Response",
      "Reports",
      "Settings",
    ]);
    expect(new Set(paths).size).toBe(paths.length);
    expect(Object.keys(routeTitles)).toEqual(paths);
  });

  it("keeps graph and status slots aligned with the desktop shell spec", () => {
    expect(graphViews).toEqual([
      "Incident Graph",
      "C2 Graph",
      "Exfiltration Graph",
      "Lateral Propagation",
      "Asset Exposure",
      "Capability Dependency",
      "Pipeline Graph",
      "Response Impact",
    ]);
    expect(statusSlots).toEqual([
      "Capture",
      "Service",
      "Attribution",
      "Risk",
      "Incidents",
      "Privacy",
      "Active Response",
    ]);
  });
});
