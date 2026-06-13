import { useEffect } from "react";
import { useUiStore } from "../stores/uiStore";

export function useReducedMotion() {
  const reducedMotion = useUiStore((state) => state.reducedMotion);
  const setReducedMotion = useUiStore((state) => state.setReducedMotion);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) {
      document.documentElement.dataset.reducedMotion = "false";
      setReducedMotion(false);
      return;
    }

    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const syncPreference = () => {
      const nextValue = mediaQuery.matches;
      document.documentElement.dataset.reducedMotion = nextValue ? "true" : "false";
      setReducedMotion(nextValue);
    };

    syncPreference();
    mediaQuery.addEventListener("change", syncPreference);
    return () => mediaQuery.removeEventListener("change", syncPreference);
  }, [setReducedMotion]);

  return reducedMotion;
}
