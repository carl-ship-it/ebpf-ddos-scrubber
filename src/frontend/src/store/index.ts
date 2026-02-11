// Global state management with Zustand.

import { create } from 'zustand';
import type { StatsSnapshot, ScrubberEvent, ScrubberStatus, RateConfig } from '../types';

const MAX_HISTORY = 300; // 5 minutes at 1s intervals
const MAX_EVENTS = 500;

interface ScrubberStore {
  // Connection state
  connected: boolean;
  setConnected: (v: boolean) => void;

  // System status
  status: ScrubberStatus | null;
  setStatus: (s: ScrubberStatus) => void;

  // Real-time stats
  currentStats: StatsSnapshot | null;
  statsHistory: StatsSnapshot[];
  pushStats: (s: StatsSnapshot) => void;

  // Events
  events: ScrubberEvent[];
  pushEvent: (e: ScrubberEvent) => void;
  clearEvents: () => void;

  // Rate config
  rateConfig: RateConfig | null;
  setRateConfig: (rc: RateConfig) => void;

  // UI state
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
}

export const useStore = create<ScrubberStore>((set) => ({
  // Connection
  connected: false,
  setConnected: (connected) => set({ connected }),

  // Status
  status: null,
  setStatus: (status) => set({ status }),

  // Stats
  currentStats: null,
  statsHistory: [],
  pushStats: (stats) =>
    set((state) => {
      const history = [...state.statsHistory, stats];
      if (history.length > MAX_HISTORY) {
        history.splice(0, history.length - MAX_HISTORY);
      }
      return { currentStats: stats, statsHistory: history };
    }),

  // Events
  events: [],
  pushEvent: (event) =>
    set((state) => {
      const events = [event, ...state.events];
      if (events.length > MAX_EVENTS) {
        events.length = MAX_EVENTS;
      }
      return { events };
    }),
  clearEvents: () => set({ events: [] }),

  // Rate config
  rateConfig: null,
  setRateConfig: (rateConfig) => set({ rateConfig }),

  // UI
  sidebarCollapsed: false,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
}));
