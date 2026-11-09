import { HubConnectionBuilder, HubConnectionState, HttpTransportType, LogLevel } from '@microsoft/signalr';
import { useEffect, useState } from 'react';
import { CaptureAccessDenied, captureRequest } from './captureApi';
import type { CaptureView } from './captureApi';
import type { GeoSnapshot } from '../geo/geoTypes';
import type { AlertSummary } from '../security/securityTypes';

type CaptureUpdate = { sequence: number; sampledAt: string; view: CaptureView; geo: GeoSnapshot; security: AlertSummary };
export type RateSample = { at: string; inbound: number; outbound: number; packets: number };
type Frame = { view?: CaptureView; geo?: GeoSnapshot; security?: AlertSummary; samples: RateSample[] };
type StreamStatus = 'locked' | 'connecting' | 'connected' | 'reconnecting';
const storageKey = 'pns-access-code';
const empty: Frame = { samples: [] };

export function useCaptureStream() {
  const [code, setCode] = useState(() => sessionStorage.getItem(storageKey) ?? '');
  const [status, setStatus] = useState<StreamStatus>(code ? 'connecting' : 'locked');
  const [rejected, setRejected] = useState(false);
  const [frame, setFrame] = useState<Frame>(empty);

  function unlock(nextCode: string) {
    setRejected(false);
    sessionStorage.setItem(storageKey, nextCode);
    setCode(nextCode);
    setStatus('connecting');
  }

  useEffect(() => {
    if (!code) return;
    const lifetime = new AbortController();
    const connection = new HubConnectionBuilder()
      .withUrl('/api/capture/live', { transport: HttpTransportType.WebSockets, accessTokenFactory: () => code })
      .configureLogging(LogLevel.None)
      .withAutomaticReconnect([0, 1000, 3000, 5000])
      .build();
    let retry: number | undefined;
    let subscription: { dispose(): void } | undefined;
    let generation = 0;

    function clear() {
      generation++;
      subscription?.dispose();
      subscription = undefined;
      setFrame(empty);
    }

    function watch() {
      if (lifetime.signal.aborted) return;
      clear();
      const current = generation;
      let sequence = 0;
      function interrupted() {
        if (lifetime.signal.aborted || current !== generation) return;
        clear();
        setStatus('reconnecting');
        if (connection.state === HubConnectionState.Connected) void connection.stop();
      }
      subscription = connection.stream<CaptureUpdate>('Watch').subscribe({
        next(update) {
          if (lifetime.signal.aborted || current !== generation || update.sequence <= sequence) return;
          sequence = update.sequence;
          setStatus('connected');
          setFrame(previous => {
            const samples = previous.view?.sessionId === update.view.sessionId ? previous.samples : [];
            const traffic = update.view.state === 'running' ? update.view.traffic : null;
            return {
              view: update.view,
              geo: update.geo,
              security: update.security,
              samples: traffic ? [...samples.slice(-299), {
                at: update.sampledAt, inbound: traffic.downloadBytesPerSecond, outbound: traffic.uploadBytesPerSecond,
                packets: traffic.packetsPerSecond,
              }] : samples,
            };
          });
        },
        error: interrupted,
        complete: interrupted,
      });
    }

    function schedule() {
      if (lifetime.signal.aborted) return;
      setStatus('reconnecting');
      window.clearTimeout(retry);
      retry = window.setTimeout(() => void connect(), 2500);
    }

    async function connect() {
      try {
        // This request distinguishes an expired code from an unavailable transport.
        await captureRequest<void>(code, 'session', { signal: lifetime.signal });
        if (lifetime.signal.aborted) return;
        await connection.start();
        watch();
      } catch (error) {
        if (lifetime.signal.aborted) return;
        if (error instanceof CaptureAccessDenied) {
          sessionStorage.removeItem(storageKey);
          setCode('');
          setRejected(true);
          setStatus('locked');
        } else schedule();
      }
    }

    connection.onreconnecting(() => {
      if (lifetime.signal.aborted) return;
      clear();
      setStatus('reconnecting');
    });
    connection.onreconnected(watch);
    connection.onclose(() => {
      if (lifetime.signal.aborted) return;
      clear();
      schedule();
    });
    void connect();

    return () => {
      lifetime.abort();
      window.clearTimeout(retry);
      subscription?.dispose();
      void connection.stop();
    };
  }, [code]);

  return { ...frame, code, status, rejected, unlock };
}
