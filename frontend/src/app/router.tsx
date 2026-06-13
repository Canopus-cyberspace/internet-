import {
  createRootRoute,
  createRoute,
  createRouter,
  useRouterState,
  type RouterHistory,
} from "@tanstack/react-router";
import { DetachedPanePage } from "../pages/detached/DetachedPanePage";
import { MainShell } from "../shared/layout/MainShell";
import { DetachedWindowShell } from "../shared/layout/DetachedWindowShell";
import { ComponentsPage } from "../pages/components/ComponentsPage";
import { GraphPage } from "../pages/graph/GraphPage";
import { InvestigationPage } from "../pages/investigation/InvestigationPage";
import { NetworkPage } from "../pages/network/NetworkPage";
import { OverviewPage } from "../pages/overview/OverviewPage";
import { ReportsPage } from "../pages/reports/ReportsPage";
import { ResponsePage } from "../pages/response/ResponsePage";
import { SettingsPage } from "../pages/settings/SettingsPage";

const rootRoute = createRootRoute({
  component: RootLayout,
});

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage,
});

const investigationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/investigation",
  component: InvestigationPage,
});

const graphRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/graph",
  component: GraphPage,
});

const componentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/components",
  component: ComponentsPage,
});

const networkRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/network",
  component: NetworkPage,
});

const responseRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/response",
  component: ResponsePage,
});

const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reports",
  component: ReportsPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

const detachedRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/detached/$paneId",
  component: DetachedPaneRoute,
});

const routeTree = rootRoute.addChildren([
  overviewRoute,
  investigationRoute,
  graphRoute,
  componentsRoute,
  networkRoute,
  responseRoute,
  reportsRoute,
  settingsRoute,
  detachedRoute,
]);

export function createAppRouter(history?: RouterHistory) {
  return createRouter({
    routeTree,
    defaultPreload: "intent",
    ...(history ? { history } : {}),
  });
}

export const router = createAppRouter();

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

function RootLayout() {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });
  return pathname.startsWith("/detached/") ? (
    <DetachedWindowShell />
  ) : (
    <MainShell />
  );
}

function DetachedPaneRoute() {
  const { paneId } = detachedRoute.useParams();
  return <DetachedPanePage paneId={paneId} />;
}
