import {
  BarChart3,
  Boxes,
  FileText,
  GitBranch,
  Home,
  Network,
  Radio,
  Settings,
  ShieldAlert,
} from "lucide-react";

export type AppRoutePath =
  | "/"
  | "/investigation"
  | "/graph"
  | "/components"
  | "/network"
  | "/response"
  | "/reports"
  | "/settings";

export interface NavigationItem {
  to: AppRoutePath;
  label: string;
  section: string;
  icon: typeof Home;
}

export const navigationItems: NavigationItem[] = [
  { to: "/", label: "Overview", section: "Workspace", icon: Home },
  {
    to: "/investigation",
    label: "Investigation",
    section: "Workspace",
    icon: ShieldAlert,
  },
  { to: "/graph", label: "Graph", section: "Workspace", icon: GitBranch },
  {
    to: "/components",
    label: "Components",
    section: "Platform",
    icon: Boxes,
  },
  { to: "/network", label: "Network", section: "Platform", icon: Network },
  { to: "/response", label: "Response", section: "Operate", icon: Radio },
  { to: "/reports", label: "Reports", section: "Operate", icon: FileText },
  { to: "/settings", label: "Settings", section: "Operate", icon: Settings },
];

export const routeTitles: Record<AppRoutePath, string> = {
  "/": "Overview",
  "/investigation": "Investigation",
  "/graph": "Graph",
  "/components": "Components",
  "/network": "Network",
  "/response": "Response",
  "/reports": "Reports",
  "/settings": "Settings",
};

export const statusSlots = [
  "Capture",
  "Service",
  "Attribution",
  "Risk",
  "Incidents",
  "Privacy",
  "Active Response",
] as const;

export const graphViews = [
  "Incident Graph",
  "C2 Graph",
  "Exfiltration Graph",
  "Lateral Propagation",
  "Asset Exposure",
  "Capability Dependency",
  "Pipeline Graph",
  "Response Impact",
] as const;

export const overviewToolbarIcon = BarChart3;
