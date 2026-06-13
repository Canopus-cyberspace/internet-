import { Link } from "@tanstack/react-router";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { navigationItems } from "../../app/navigation";
import { useUiStore } from "../../stores/uiStore";

export function NavigationTree() {
  const collapsed = useUiStore((state) => state.sidebarCollapsed);
  const setCollapsed = useUiStore((state) => state.setSidebarCollapsed);
  const sections = [...new Set(navigationItems.map((item) => item.section))];

  return (
    <aside className="navigation-tree" data-collapsed={collapsed}>
      <div className="tree-header">
        <strong>Workspace</strong>
        <button
          type="button"
          className="tree-toggle"
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          {collapsed ? (
            <PanelLeftOpen size={14} aria-hidden="true" />
          ) : (
            <PanelLeftClose size={14} aria-hidden="true" />
          )}
        </button>
      </div>
      <nav aria-label="Primary navigation" className="scroll-region">
        {sections.map((section) => (
          <div className="tree-section" key={section}>
            <span className="tree-section-label">{section}</span>
            {navigationItems
              .filter((item) => item.section === section)
              .map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className="tree-link"
                    activeProps={{ className: "tree-link active" }}
                  >
                    <Icon size={16} aria-hidden="true" />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
          </div>
        ))}
      </nav>
    </aside>
  );
}
