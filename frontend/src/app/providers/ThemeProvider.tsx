import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useMemo,
} from "react";
import { useUiStore, type ThemeMode } from "../../stores/uiStore";
import { useReducedMotion } from "../../shared/useReducedMotion";

/** The resolved theme actually applied to `<html>`. */
export type ResolvedTheme = "light" | "dark" | "deep-dark";

interface ThemeContextValue {
  theme: ThemeMode;
  /** The effective theme after "system" resolution. */
  resolved: ResolvedTheme;
  setTheme: (theme: ThemeMode) => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

interface ThemeProviderProps {
  children: ReactNode;
}

/** Map a raw ThemeMode to the effective data-theme value. */
function resolveTheme(mode: ThemeMode): ResolvedTheme {
  if (mode === "system") {
    if (typeof window === "undefined" || !window.matchMedia) {
      return "dark";
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }
  return mode;
}

/** Set the `color-scheme` CSS property so native controls follow the theme. */
function applyColorScheme(resolved: ResolvedTheme) {
  document.documentElement.style.colorScheme =
    resolved === "light" ? "light" : "dark";
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const theme = useUiStore((state) => state.theme);
  const setTheme = useUiStore((state) => state.setTheme);
  useReducedMotion();

  const resolved = useMemo(() => resolveTheme(theme), [theme]);

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
    applyColorScheme(resolved);
  }, [resolved]);

  // Watch for OS-level preference changes when in "system" mode
  useEffect(() => {
    if (theme !== "system") return;
    if (typeof window === "undefined" || !window.matchMedia) return;

    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      // Re-resolve and re-apply. The store value is still "system",
      // so we trigger a re-render by nudging the data attribute.
      const next = resolveTheme("system");
      document.documentElement.dataset.theme = next;
      applyColorScheme(next);
    };

    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [theme]);

  const value = useMemo(
    () => ({ theme, resolved, setTheme }),
    [theme, resolved, setTheme],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return value;
}
