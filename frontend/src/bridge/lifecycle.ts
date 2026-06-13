import { getCurrentWindow } from "@tauri-apps/api/window";
import { invokeCore } from "./tauri/invoke";

export function shutdownApp() {
  return invokeCore<void>("shutdown_app");
}

export async function registerWindowCloseShutdown() {
  const currentWindow = getCurrentWindow();
  if (currentWindow.label !== "main") {
    return () => {};
  }
  return currentWindow.onCloseRequested((event) => {
    event.preventDefault();
    void shutdownApp().catch(() => {
      void currentWindow.destroy();
    });
  });
}
