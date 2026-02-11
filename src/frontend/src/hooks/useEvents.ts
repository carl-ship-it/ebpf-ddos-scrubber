import { useMemo } from 'react';
import { useStore } from '../store';
import type { ScrubberEvent } from '../types';

/**
 * Returns the event list with optional filtering.
 */
export function useEvents(filter?: {
  attackType?: string;
  action?: string;
  protocol?: number;
}): ScrubberEvent[] {
  const events = useStore((s) => s.events);

  return useMemo(() => {
    if (!filter) return events;
    return events.filter((e) => {
      if (filter.attackType && e.attackType !== filter.attackType) return false;
      if (filter.action && e.action !== filter.action) return false;
      if (filter.protocol !== undefined && e.protocol !== filter.protocol) return false;
      return true;
    });
  }, [events, filter]);
}

/**
 * Returns event counts grouped by attack type (for the last N events).
 */
export function useEventCounts(): Record<string, number> {
  const events = useStore((s) => s.events);

  return useMemo(() => {
    const counts: Record<string, number> = {};
    for (const e of events) {
      const key = e.attackType || 'unknown';
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [events]);
}
