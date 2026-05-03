'use client';

// JobTerminal mounts an xterm.js instance and bridges it to the htcondor-api
// WebSocket SSH-to-job endpoint. The wire protocol is intentionally tiny:
//
//   * Binary frames in either direction = raw stdio bytes.
//   * Text frames = JSON control messages.
//       client → server : {type:"resize",cols,rows}, {type:"signal",name},
//                          {type:"close"}
//       server → client : {type:"exit",code,reason}
//
// The matching server-side handler is httpserver/handlers_ssh.go.

import { useEffect, useRef, useState } from 'react';
import { Terminal, type IDisposable } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { api } from '@/lib/api';

type ConnState = 'connecting' | 'open' | 'closed' | 'error';

interface ExitFrame {
  type: 'exit';
  code?: number;
  reason?: string;
}

export function JobTerminal({ jobID }: { jobID: string }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const onDataDisposable = useRef<IDisposable | null>(null);

  const [state, setState] = useState<ConnState>('connecting');
  const [exit, setExit] = useState<ExitFrame | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      theme: {
        background: '#0b0f17',
        foreground: '#d6deeb',
        cursor: '#c5e478',
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    termRef.current = term;
    fitRef.current = fit;
    fit.fit();

    // Establish the WebSocket *after* the terminal has its initial size so
    // the server gets sane initial dims before the first resize frame.
    const cols = term.cols;
    const rows = term.rows;
    const url = api.jobs.sshWebSocketUrl(jobID, cols, rows);
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    const sendText = (msg: object) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msg));
      }
    };

    ws.addEventListener('open', () => {
      setState('open');
      term.focus();
    });

    ws.addEventListener('error', () => {
      setState('error');
      setErrorMsg('WebSocket error — see browser devtools for details.');
    });

    ws.addEventListener('close', () => {
      setState((s) => (s === 'error' ? s : 'closed'));
    });

    ws.addEventListener('message', (ev) => {
      if (typeof ev.data === 'string') {
        // Text frame — JSON control message.
        try {
          const msg = JSON.parse(ev.data) as { type?: string } & ExitFrame;
          if (msg.type === 'exit') {
            setExit({ type: 'exit', code: msg.code, reason: msg.reason });
          }
        } catch {
          // Non-JSON text frame; ignore.
        }
        return;
      }
      // Binary frame — stdio bytes. xterm.js's `write` accepts Uint8Array.
      const buf = ev.data as ArrayBuffer;
      term.write(new Uint8Array(buf));
    });

    onDataDisposable.current = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    const onResize = () => {
      if (!fit) return;
      try {
        fit.fit();
      } catch {
        // xterm.js can throw if the container has zero size; ignore.
      }
      sendText({ type: 'resize', cols: term.cols, rows: term.rows });
    };
    window.addEventListener('resize', onResize);

    return () => {
      window.removeEventListener('resize', onResize);
      onDataDisposable.current?.dispose();
      try {
        if (ws.readyState === WebSocket.OPEN) {
          sendText({ type: 'close' });
        }
        ws.close();
      } catch {
        // ignore
      }
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      wsRef.current = null;
    };
  }, [jobID]);

  const banner =
    state === 'connecting'
      ? 'Connecting…'
      : state === 'open' && !exit
        ? null
        : exit
          ? `Session ended (code=${exit.code ?? 0}${exit.reason ? `, ${exit.reason}` : ''})`
          : state === 'error'
            ? errorMsg ?? 'Connection error'
            : 'Disconnected';

  return (
    <div className="flex flex-col gap-2">
      {banner && (
        <div
          className={`rounded border px-3 py-1.5 text-xs ${
            state === 'error'
              ? 'border-red-200 bg-red-50 text-red-700'
              : 'border-gray-200 bg-gray-50 text-gray-600'
          }`}
        >
          {banner}
        </div>
      )}
      <div
        ref={containerRef}
        className="w-full rounded border border-gray-300 bg-[#0b0f17] p-2"
        // xterm.js sizes its rows/cols against the container. Give it enough
        // height to be useful by default; the user can resize the window.
        style={{ height: '480px' }}
      />
    </div>
  );
}
