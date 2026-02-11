import { useEffect } from 'react';
import { useStore } from '../store';
import { generateStats, generateEvent, generateStatus } from '../mock/generator';

/**
 * Hook that feeds mock data into the Zustand store for demo/dev.
 * Replaces useRealtimeConnection when no backend is available.
 */
export function useMockData() {
  const pushStats = useStore((s) => s.pushStats);
  const pushEvent = useStore((s) => s.pushEvent);
  const setStatus = useStore((s) => s.setStatus);
  const setConnected = useStore((s) => s.setConnected);

  useEffect(() => {
    setConnected(true);
    setStatus(generateStatus());

    // Feed stats every second
    const statsIv = setInterval(() => {
      pushStats(generateStats());
      setStatus(generateStatus());
    }, 1000);

    // Feed events at random intervals (2-5 per second)
    const eventIv = setInterval(() => {
      pushEvent(generateEvent());
      if (Math.random() > 0.4) pushEvent(generateEvent());
      if (Math.random() > 0.7) pushEvent(generateEvent());
    }, 400);

    // Push initial data
    pushStats(generateStats());

    return () => {
      clearInterval(statsIv);
      clearInterval(eventIv);
    };
  }, [pushStats, pushEvent, setStatus, setConnected]);
}
