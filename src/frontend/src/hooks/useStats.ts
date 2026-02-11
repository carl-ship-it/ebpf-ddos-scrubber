import { useEffect } from 'react';
import { useStore } from '../store';
import { realtimeClient } from '../api/ws';
import { getStats, getStatus } from '../api/client';

/**
 * Hook that connects to the realtime WebSocket and polls initial data.
 * Should be called once at the app root level.
 */
export function useRealtimeConnection() {
  const pushStats = useStore((s) => s.pushStats);
  const pushEvent = useStore((s) => s.pushEvent);
  const setStatus = useStore((s) => s.setStatus);
  const setConnected = useStore((s) => s.setConnected);

  useEffect(() => {
    // Initial data fetch
    getStatus()
      .then(setStatus)
      .catch((err) => console.error('Failed to fetch status:', err));

    getStats()
      .then(pushStats)
      .catch((err) => console.error('Failed to fetch stats:', err));

    // WebSocket subscriptions
    const unsubStats = realtimeClient.onStats((stats) => {
      pushStats(stats);
    });

    const unsubEvents = realtimeClient.onEvent((event) => {
      pushEvent(event);
    });

    // Connect
    realtimeClient.connect();

    // Poll connection state
    const interval = setInterval(() => {
      setConnected(realtimeClient.connected);
    }, 1000);

    return () => {
      unsubStats();
      unsubEvents();
      clearInterval(interval);
      realtimeClient.disconnect();
    };
  }, [pushStats, pushEvent, setStatus, setConnected]);
}

/**
 * Returns the latest stats snapshot.
 */
export function useCurrentStats() {
  return useStore((s) => s.currentStats);
}

/**
 * Returns the stats history array for charting.
 */
export function useStatsHistory() {
  return useStore((s) => s.statsHistory);
}
