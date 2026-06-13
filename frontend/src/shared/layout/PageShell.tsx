import type { ReactNode } from "react";

interface PageShellProps {
  title: string;
  eyebrow: string;
  children: ReactNode;
}

export function PageShell({ title, eyebrow, children }: PageShellProps) {
  return (
    <section className="page-shell">
      <header className="page-header">
        <span>{eyebrow}</span>
        <h1>{title}</h1>
      </header>
      <div className="page-body scroll-region">{children}</div>
    </section>
  );
}
