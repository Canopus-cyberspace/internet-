import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";
import { setInvokeCoreForTests } from "../bridge/tauri/invoke";
import { createAppRouter } from "./router";

describe("detached pane route", () => {
  afterEach(() => {
    setInvokeCoreForTests(null);
  });

  it("renders the native detached graph page for /detached/graph", async () => {
    setInvokeCoreForTests(async () => {
      throw new Error("detached graph route SSR should render an honest empty view");
    });

    const testRouter = createAppRouter(
      createMemoryHistory({
        initialEntries: ["/detached/graph"],
      }),
    );
    await testRouter.load();

    const markup = renderToStaticMarkup(
      withQueryClient(<RouterProvider router={testRouter} />),
    );

    expect(testRouter.state.location.pathname).toBe("/detached/graph");
    expect(markup).toContain("detached-graph / native window");
    expect(markup).toContain("Graph types");
    expect(markup).toContain("No graph nodes");
    expect(markup).not.toContain(["MOCK", "ONLY"].join("_"));
    expect(markup).toContain("Node detail");
  });

  it.each([
    ["/detached/inspector", "detached-inspector / native window", "Inspector read model"],
    ["/detached/evidence", "detached-evidence / native window", "Evidence read model"],
    ["/detached/timeline", "detached-timeline / native window", "Timeline read model"],
  ])("renders the native detached read-model page for %s", async (route, label, title) => {
    const testRouter = createAppRouter(
      createMemoryHistory({
        initialEntries: [route],
      }),
    );
    await testRouter.load();

    const markup = renderToStaticMarkup(
      withQueryClient(<RouterProvider router={testRouter} />),
    );

    expect(testRouter.state.location.pathname).toBe(route);
    expect(markup).toContain(label);
    expect(markup).toContain(title);
  });

  it("keeps the detached route parameterized as /detached/:paneId", async () => {
    const testRouter = createAppRouter(
      createMemoryHistory({
        initialEntries: ["/detached/graph"],
      }),
    );
    await testRouter.load();

    expect(testRouter.state.matches.at(-1)?.routeId).toBe("/detached/$paneId");
    expect(testRouter.state.matches.at(-1)?.params).toEqual({
      paneId: "graph",
    });
  });
});

function withQueryClient(element: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={queryClient}>{element}</QueryClientProvider>;
}
