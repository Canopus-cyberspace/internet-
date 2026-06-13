import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { createAppRouter } from "../../app/router";
import { navigationItems } from "../../app/navigation";
import { ThemeProvider } from "../../app/providers/ThemeProvider";

describe("NavigationTree interactions", () => {
  it("renders every sidebar route as a normal navigation link", async () => {
    const testRouter = createAppRouter(
      createMemoryHistory({
        initialEntries: ["/"],
      }),
    );
    await testRouter.load();

    const markup = renderToStaticMarkup(
      withQueryClient(<RouterProvider router={testRouter} />),
    );

    for (const item of navigationItems) {
      expect(markup).toContain(item.label);
      expect(markup).toContain(`href="${item.to}"`);
    }
  });
});

function withQueryClient(element: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>{element}</ThemeProvider>
    </QueryClientProvider>
  );
}
