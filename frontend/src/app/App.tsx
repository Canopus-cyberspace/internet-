import { RouterProvider } from "@tanstack/react-router";
import { ErrorBoundary } from "./providers/ErrorBoundary";
import { QueryProvider } from "./providers/QueryProvider";
import { TauriEventProvider } from "./providers/TauriEventProvider";
import { ThemeProvider } from "./providers/ThemeProvider";
import { router } from "./router";
import { registerDefaultRenderers } from "../shared/renderers";
import { PixelCharacter } from "../shared/ambient/PixelCharacter";

registerDefaultRenderers();

export function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <QueryProvider>
          <TauriEventProvider>
            <RouterProvider router={router} />
            <PixelCharacter />
          </TauriEventProvider>
        </QueryProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
