import { useMemo } from "react";

export interface InteractionStateOptions {
  readonly active?: boolean;
  readonly degraded?: boolean;
  readonly disabled?: boolean;
  readonly empty?: boolean;
  readonly error?: boolean;
  readonly loading?: boolean;
  readonly selected?: boolean;
}

export function interactionStateClass(
  baseClass: string,
  state: InteractionStateOptions,
) {
  const modifiers = Object.entries(state)
    .filter(([, enabled]) => Boolean(enabled))
    .map(([key]) => `is-${key}`);
  return [baseClass, ...modifiers].join(" ");
}

export function useInteractionStates(
  baseClass: string,
  state: InteractionStateOptions,
) {
  return useMemo(
    () => interactionStateClass(baseClass, state),
    [
      baseClass,
      state.active,
      state.degraded,
      state.disabled,
      state.empty,
      state.error,
      state.loading,
      state.selected,
    ],
  );
}
