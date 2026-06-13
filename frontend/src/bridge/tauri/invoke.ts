import { mapCoreError } from "./errors";
import { assertCoreCommandAllowed, type CoreCommandName } from "./permissions";

type InvokeFn = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

let invokeOverride: InvokeFn | null = null;

export function setInvokeCoreForTests(invoke: InvokeFn | null) {
  invokeOverride = invoke;
}

export async function invokeCore<T>(
  command: CoreCommandName,
  args?: Record<string, unknown>,
): Promise<T> {
  assertCoreCommandAllowed(command);

  try {
    const invoke = invokeOverride ?? (await loadTauriInvoke());
    return await invoke<T>(command, args);
  } catch (error) {
    throw mapCoreError(error);
  }
}

async function loadTauriInvoke(): Promise<InvokeFn> {
  const module = await import("@tauri-apps/api/core");
  return module.invoke as InvokeFn;
}
