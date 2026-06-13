import { create } from "zustand";
import type {
  NavigationTargetKindDto,
  NavigationViewKindDto,
} from "../bridge/dto/navigation";

export interface NavigationSelection {
  source_view: NavigationViewKindDto;
  target_kind: NavigationTargetKindDto;
  target_id: string;
}

interface NavigationState {
  current: NavigationSelection | null;
  breadcrumbs: NavigationSelection[];
  open: (selection: NavigationSelection) => void;
  back: () => void;
  clear: () => void;
}

const MAX_BREADCRUMBS = 8;

export const useNavigationStore = create<NavigationState>((set) => ({
  current: null,
  breadcrumbs: [],
  open: (selection) =>
    set((state) => {
      const prior = state.current ? [...state.breadcrumbs, state.current] : state.breadcrumbs;
      return {
        current: selection,
        breadcrumbs: prior.slice(-MAX_BREADCRUMBS),
      };
    }),
  back: () =>
    set((state) => {
      const current = state.breadcrumbs.at(-1) ?? null;
      return {
        current,
        breadcrumbs: state.breadcrumbs.slice(0, -1),
      };
    }),
  clear: () => set({ current: null, breadcrumbs: [] }),
}));
