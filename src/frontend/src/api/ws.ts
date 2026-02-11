// WebSocket client for real-time stats and events streaming.

import type { StatsSnapshot, ScrubberEvent } from '../types';

export type WSMessageType = 'stats' | 'event';

export interface WSMessage {
  type: WSMessageType;
  data: StatsSnapshot | ScrubberEvent;
}

type StatsHandler = (stats: StatsSnapshot) => void;
type EventHandler = (event: ScrubberEvent) => void;

export class RealtimeClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectInterval = 3000;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private statsHandlers: StatsHandler[] = [];
  private eventHandlers: EventHandler[] = [];
  private _connected = false;

  constructor(url?: string) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.url = url ?? `${protocol}//${window.location.host}/ws/realtime`;
  }

  get connected(): boolean {
    return this._connected;
  }

  connect(): void {
    if (this.ws) return;

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        this._connected = true;
        console.log('[WS] connected');
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }
      };

      this.ws.onmessage = (ev) => {
        try {
          const msg: WSMessage = JSON.parse(ev.data);
          this.dispatch(msg);
        } catch (err) {
          console.warn('[WS] failed to parse message:', err);
        }
      };

      this.ws.onclose = () => {
        this._connected = false;
        this.ws = null;
        console.log('[WS] disconnected, reconnecting...');
        this.scheduleReconnect();
      };

      this.ws.onerror = (err) => {
        console.error('[WS] error:', err);
        this.ws?.close();
      };
    } catch (err) {
      console.error('[WS] connection failed:', err);
      this.scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onclose = null; // prevent reconnect
      this.ws.close();
      this.ws = null;
    }
    this._connected = false;
  }

  onStats(handler: StatsHandler): () => void {
    this.statsHandlers.push(handler);
    return () => {
      this.statsHandlers = this.statsHandlers.filter((h) => h !== handler);
    };
  }

  onEvent(handler: EventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      this.eventHandlers = this.eventHandlers.filter((h) => h !== handler);
    };
  }

  private dispatch(msg: WSMessage): void {
    switch (msg.type) {
      case 'stats':
        for (const h of this.statsHandlers) {
          h(msg.data as StatsSnapshot);
        }
        break;
      case 'event':
        for (const h of this.eventHandlers) {
          h(msg.data as ScrubberEvent);
        }
        break;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.reconnectInterval);
  }
}

// Singleton instance
export const realtimeClient = new RealtimeClient();
