import { Outlet } from "@tanstack/react-router";
import { ParticleBackground } from "../ambient/ParticleBackground";

export function DetachedWindowShell() {
  return (
    <div className="detached-app-frame">
      <ParticleBackground />
      <Outlet />
    </div>
  );
}
