import { create } from "zustand";

export interface BannerNotification {
  id: string;
  level: "info" | "warning" | "critical";
  message: string;
}

interface NotificationStore {
  banners: BannerNotification[];
  toasts: BannerNotification[];
  streamBadgeCount: number;
  incrementStreamBadge: () => void;
  resetStreamBadge: () => void;
  pushBanner: (banner: BannerNotification) => void;
  pushToast: (toast: BannerNotification) => void;
  dismissBanner: (id: string) => void;
  dismissToast: (id: string) => void;
}

export const useNotificationStore = create<NotificationStore>((set) => ({
  banners: [],
  toasts: [],
  streamBadgeCount: 0,
  incrementStreamBadge: () =>
    set((state) => ({ streamBadgeCount: Math.min(99, state.streamBadgeCount + 1) })),
  resetStreamBadge: () => set({ streamBadgeCount: 0 }),
  pushBanner: (banner) =>
    set((state) => ({
      banners: [banner, ...state.banners].slice(0, 5),
    })),
  pushToast: (toast) =>
    set((state) => ({
      toasts: [toast, ...state.toasts].slice(0, 8),
    })),
  dismissBanner: (id) =>
    set((state) => ({
      banners: state.banners.filter((banner) => banner.id !== id),
    })),
  dismissToast: (id) =>
    set((state) => ({
      toasts: state.toasts.filter((toast) => toast.id !== id),
    })),
}));
