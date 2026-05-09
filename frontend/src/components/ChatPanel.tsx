'use client';

// LLM-backed chat panel for the jobs view. Talks to the Go server's
// /api/v1/chat endpoint via the AI SDK's DefaultChatTransport, which
// reads the SSE-of-UIMessageChunks stream the Go side emits.
//
// Three things drive whether this component renders at all (decided
// by the parent page):
//
//   1. /api/v1/chat/info reports enabled=true (LLM key + MCP on).
//   2. The user has > 0 visible jobs (no point chatting about an
//      empty queue).
//   3. The hosting page is the jobs list — we don't surface this
//      anywhere else right now.
//
// Phase 4 wires in the client-side tools (set_filter, expand_batch,
// highlight_job); Phase 5 wires the confirmation UX for destructive
// server-side tools. This file is intentionally narrow for now: a
// scrolling transcript + an input.

import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport, type UIMessage } from 'ai';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '@/lib/api';

// Tool names that pause for user approval before the engine
// executes them. Mirrors handlers_chat_tools.go's confirm:true
// list. Auto-approve checkboxes drive whether each one runs
// without a click.
const CONFIRMABLE_TOOLS = ['hold_job', 'release_job', 'remove_job'] as const;
type ConfirmableTool = (typeof CONFIRMABLE_TOOLS)[number];

const AUTO_APPROVE_LS_KEY = 'htcondor-api.chat.auto_approve';

// loadAutoApprove pulls the persisted auto-approve set from
// localStorage. Per-browser, per-user — we don't sync this across
// tabs / devices because operator override of the confirmation gate
// is exactly the kind of decision that should re-trigger when the
// user moves to a new machine.
function loadAutoApprove(): Set<ConfirmableTool> {
  if (typeof window === 'undefined') return new Set();
  try {
    const raw = window.localStorage.getItem(AUTO_APPROVE_LS_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) return new Set();
    return new Set(
      arr.filter((x): x is ConfirmableTool =>
        CONFIRMABLE_TOOLS.includes(x as ConfirmableTool),
      ),
    );
  } catch {
    return new Set();
  }
}

function saveAutoApprove(set: Set<ConfirmableTool>) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(
      AUTO_APPROVE_LS_KEY,
      JSON.stringify(Array.from(set)),
    );
  } catch {
    // localStorage can throw under privacy modes; the auto-approve
    // is purely a UX convenience, so a failure here is acceptable.
  }
}

// ChatPanelHooks lets the parent page expose imperative handlers the
// chat's client-side tools (Phase 4) will eventually wire into. We
// declare the shape here so the typings stay co-located with the
// chat component, even though the implementations (set the filter,
// expand a batch, etc.) live on the parent.
//
// Phase 3 leaves this unused; Phase 4 promotes it from a stub to the
// real client-side tool dispatch table.
export interface ChatPanelHooks {
  setFilter: (constraint: string) => void;
  expandBatch: (clusterId: number) => void;
  highlightJob: (clusterId: number, procId: number) => void;
}

interface ChatPanelProps {
  // Whether the parent has decided the chat is allowed to render
  // (info probe + jobs-count gate). When false the component
  // returns null — the host page typically hides via a wrapper too,
  // but this guard keeps a misuse from blowing up the page.
  visible: boolean;
  hooks?: ChatPanelHooks;
}

// ChatPanel is the actual UI. Sits below the jobs table per
// architectural decision; collapses to a small "Ask about your
// jobs" pill until clicked.
export function ChatPanel({ visible, hooks }: ChatPanelProps) {
  // Auto-approve set + pending-approval set. Both flow into the
  // transport's body resolver via refs so the closure inside
  // DefaultChatTransport always sees the latest state without
  // having to rebuild the transport on every render.
  const [autoApprove, setAutoApprove] = useState<Set<ConfirmableTool>>(
    () => loadAutoApprove(),
  );
  useEffect(() => {
    saveAutoApprove(autoApprove);
  }, [autoApprove]);

  const approvedIdsRef = useRef<string[]>([]);
  const autoApproveRef = useRef<Set<ConfirmableTool>>(autoApprove);
  // Mirror autoApprove into the ref via effect so the body
  // resolver inside the (memoized) transport always sees the
  // latest value without us writing to the ref during render
  // (which React's strict rules forbid).
  useEffect(() => {
    autoApproveRef.current = autoApprove;
  }, [autoApprove]);

  // useMemo so the transport instance is stable across re-renders.
  // The body resolver runs per-POST, so it sees the *latest* values
  // off the refs every time — we use that to thread approvals + the
  // auto-approve set into the request body the engine reads.
  // The body resolver is invoked per-POST, not at render time —
  // reading the ref's current value inside the closure happens
  // when the SDK is about to send a request, which is exactly
  // when we want the latest approvedIds + autoApprove set. The
  // react-hooks/refs lint can't see through the closure to know
  // the read isn't happening during render, so disable it
  // around the definition site.
  /* eslint-disable react-hooks/refs */
  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: api.chat.streamURL,
        // Send our session cookie / bearer header just like every
        // other authenticated request. Without `include`, the SDK's
        // fetch defaults to same-origin and the cookie's path
        // restriction may cause it to be omitted (we're on an
        // arbitrary subpath of the SPA).
        credentials: 'include',
        body: () => ({
          approved_tool_use_ids: approvedIdsRef.current,
          auto_approve: Array.from(autoApproveRef.current),
        }),
      }),
    [],
  );
  /* eslint-enable react-hooks/refs */

  // The SDK's onToolCall returns void; the tool result has to be
  // sent in via the chat helpers' addToolResult after dispatch. We
  // park addToolResult on a ref so the closure inside onToolCall
  // can reach it without a init-vs-return cycle (onToolCall is
  // initialized BEFORE the helpers are returned).
  const addToolResultRef = useRef<
    | ((opts: { tool: string; toolCallId: string; output: unknown }) => void)
    | null
  >(null);

  const handleToolCall = useMemo(
    () =>
      ({
        toolCall,
      }: {
        toolCall: { toolName: string; toolCallId: string; input: unknown };
      }) => {
        const send = addToolResultRef.current;
        if (!send) return;
        const reply = (output: unknown) =>
          send({
            tool: toolCall.toolName,
            toolCallId: toolCall.toolCallId,
            output,
          });
        try {
          const input = (toolCall.input ?? {}) as Record<string, unknown>;
          switch (toolCall.toolName) {
            case 'set_filter': {
              const q = typeof input.query === 'string' ? input.query : '';
              hooks?.setFilter(q);
              reply({ ok: true, applied_query: q });
              return;
            }
            case 'expand_batch': {
              const cid = Number(input.cluster_id);
              if (!Number.isFinite(cid) || cid <= 0) {
                reply({ ok: false, error: 'cluster_id must be a positive integer' });
                return;
              }
              hooks?.expandBatch(cid);
              reply({ ok: true, expanded_cluster_id: cid });
              return;
            }
            case 'highlight_job': {
              const cid = Number(input.cluster_id);
              const pid = Number(input.proc_id);
              if (!Number.isFinite(cid) || !Number.isFinite(pid)) {
                reply({ ok: false, error: 'cluster_id and proc_id must be integers' });
                return;
              }
              hooks?.highlightJob(cid, pid);
              reply({ ok: true, highlighted: `${cid}.${pid}` });
              return;
            }
            default:
              reply({
                ok: false,
                error: `unknown client-side tool: ${toolCall.toolName}`,
              });
          }
        } catch (e) {
          reply({ ok: false, error: e instanceof Error ? e.message : String(e) });
        }
      },
    [hooks],
  );

  const { messages, sendMessage, status, error, stop, addToolResult } =
    useChat({
      transport,
      onToolCall: handleToolCall,
    });

  // Mirror the latest addToolResult into the ref via effect (same
  // motivation as autoApproveRef above — onToolCall is initialized
  // before useChat returns the helpers, so we have to thread the
  // current binding via a ref, but write to it OUTSIDE render).
  useEffect(() => {
    addToolResultRef.current = addToolResult as unknown as typeof addToolResultRef.current;
  }, [addToolResult]);

  // Pull the pending approvals off the message stream. The server
  // emits a tool-approval-request chunk for each destructive tool
  // call that's neither pre-approved nor auto-approved; the SDK
  // surfaces those as message parts with state="input-approval-required"
  // (or, in our dynamic-tool case, as parts whose type begins with
  // "tool-" and whose state needs explicit user action). We
  // identify them by toolCallId so we can render an Approve / Reject
  // card per-pending and dispatch on click.
  const pending = useMemo(() => collectPendingApprovals(messages), [messages]);

  // Approve handler — drop the toolCallId into the approvedIds list
  // (read by the transport body resolver) and trigger another turn
  // by sending a synthetic "Yes." user message. The engine sees the
  // tool_use already in history, finds its id in the approval set,
  // and executes server-side.
  const approve = useCallback(
    (toolCallId: string) => {
      approvedIdsRef.current = [...approvedIdsRef.current, toolCallId];
      void sendMessage({ text: 'Approved.' });
    },
    [sendMessage],
  );

  // Reject — emit a synthetic tool-result indicating denial, then
  // continue. The LLM sees a denied result and can apologize / move
  // on. Doesn't add to approvedIds.
  const reject = useCallback(
    (toolCallId: string, toolName: string) => {
      const send = addToolResultRef.current;
      if (!send) return;
      send({
        tool: toolName,
        toolCallId,
        output: { ok: false, error: 'User denied this action.' },
      });
    },
    [],
  );

  const toggleAutoApprove = useCallback((tool: ConfirmableTool) => {
    setAutoApprove((prev) => {
      const next = new Set(prev);
      if (next.has(tool)) next.delete(tool);
      else next.add(tool);
      return next;
    });
  }, []);

  const [input, setInput] = useState('');
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const [open, setOpen] = useState(false);

  // Auto-scroll to the bottom on new messages / streaming deltas.
  useEffect(() => {
    if (!transcriptRef.current) return;
    transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight;
  }, [messages]);

  if (!visible) return null;

  if (!open) {
    return (
      <div className="mt-4 flex justify-start">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="rounded-full border border-gray-300 bg-white px-4 py-1.5 text-xs text-gray-700 shadow-sm hover:bg-gray-50"
          aria-label="Open chat assistant"
        >
          Ask about your jobs
        </button>
      </div>
    );
  }

  const submit = () => {
    const text = input.trim();
    if (!text || status === 'streaming' || status === 'submitted') return;
    setInput('');
    void sendMessage({ text });
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  return (
    <div className="mt-4 rounded-lg border border-gray-200 bg-white shadow-sm">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-gray-200 px-3 py-2">
        <h2 className="text-sm font-semibold text-gray-900">Job assistant</h2>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-gray-600">
          <span>Auto-approve:</span>
          {CONFIRMABLE_TOOLS.map((t) => (
            <label key={t} className="flex items-center gap-1 cursor-pointer">
              <input
                type="checkbox"
                checked={autoApprove.has(t)}
                onChange={() => toggleAutoApprove(t)}
                className="rounded border-gray-300"
              />
              <span className="font-mono">{t.replace('_job', '')}</span>
            </label>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2 text-xs">
          {(status === 'streaming' || status === 'submitted') && (
            <button
              type="button"
              onClick={() => stop()}
              className="rounded border border-gray-300 px-2 py-0.5 text-gray-600 hover:bg-gray-50"
            >
              Stop
            </button>
          )}
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="text-gray-500 hover:text-gray-800"
            aria-label="Close chat"
          >
            ×
          </button>
        </div>
      </div>

      <div
        ref={transcriptRef}
        className="max-h-80 overflow-y-auto px-3 py-2 space-y-3 text-sm"
      >
        {messages.length === 0 && (
          <p className="text-xs italic text-gray-500">
            Ask things like &ldquo;how many of my jobs are held?&rdquo;,
            &ldquo;why is my last batch stuck?&rdquo;, or &ldquo;release everything that&apos;s
            held with code 13&rdquo;.
          </p>
        )}
        {messages.map((m) => (
          <MessageView key={m.id} m={m} />
        ))}
        {pending.map((p) => (
          <ApprovalCard
            key={p.toolCallId}
            request={p}
            onApprove={() => approve(p.toolCallId)}
            onReject={() => reject(p.toolCallId, p.toolName)}
          />
        ))}
        {error && (
          <div className="rounded border border-red-200 bg-red-50 p-2 text-xs text-red-800">
            {error.message || 'Chat error'}
          </div>
        )}
      </div>

      <div className="border-t border-gray-200 p-2">
        <div className="flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Ask about your jobs…"
            rows={2}
            disabled={status === 'streaming' || status === 'submitted'}
            className="flex-1 min-w-0 resize-none rounded border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400 disabled:bg-gray-50"
          />
          <button
            type="button"
            onClick={submit}
            disabled={
              !input.trim() ||
              status === 'streaming' ||
              status === 'submitted'
            }
            className="self-stretch rounded bg-brand-600 px-3 py-1 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            Send
          </button>
        </div>
        <p className="mt-1 text-[10px] text-gray-400">
          The assistant only sees your own jobs — every tool call is
          scoped to your username server-side.
        </p>
      </div>
    </div>
  );
}

// MessageView renders one message's parts. The AI SDK packs text
// + tool calls + tool results as a heterogeneous parts array; we
// walk it and render each kind. Phase 5 adds the approval-card
// branch on top.
function MessageView({ m }: { m: UIMessage }) {
  const isUser = m.role === 'user';
  return (
    <div className={isUser ? 'flex justify-end' : 'flex justify-start'}>
      <div
        className={`max-w-[85%] rounded px-3 py-1.5 ${
          isUser ? 'bg-brand-50 text-gray-800' : 'bg-gray-50 text-gray-800'
        }`}
      >
        {m.parts.map((p, i) => (
          <PartView key={i} part={p} />
        ))}
      </div>
    </div>
  );
}

// PendingApproval describes one tool-use waiting for user
// approval. Constructed from the message stream — we don't keep
// our own list, we derive from messages so it stays consistent
// with what the SDK has parsed.
interface PendingApproval {
  toolCallId: string;
  toolName: string;
  input: unknown;
}

// collectPendingApprovals walks the messages and returns any
// tool parts that are awaiting approval. The SDK exposes the
// tool-approval-request as a chunk that updates a tool part's
// `state` to "input-approval-required" (or for our dynamic-tool
// flow, a state we recognize via a permissive walk). A tool part
// that has reached "output-available" or "output-error" is
// resolved; we filter those out.
function collectPendingApprovals(messages: UIMessage[]): PendingApproval[] {
  const out: PendingApproval[] = [];
  for (const m of messages) {
    if (m.role !== 'assistant') continue;
    for (const part of m.parts) {
      // Loose typing — the v6 part union is broad and tool parts
      // appear with several discriminator keys depending on
      // dynamic vs structured tool registration. We look for any
      // part whose state field signals "approval required" and
      // that hasn't been resolved yet.
      const tp = part as unknown as {
        type: string;
        toolName?: string;
        toolCallId?: string;
        state?: string;
        input?: unknown;
        output?: unknown;
        errorText?: string;
      };
      if (typeof tp.type !== 'string') continue;
      const isToolPart =
        tp.type === 'dynamic-tool' || tp.type.startsWith('tool-');
      if (!isToolPart) continue;
      // Resolved already — skip.
      if (tp.state === 'output-available' || tp.state === 'output-error')
        continue;
      // Awaiting approval. Both "input-approval-required" (the
      // SDK's structured state) and our own "approval-required"
      // shape from the protocol writer land here.
      if (
        tp.state !== 'input-approval-required' &&
        tp.state !== 'approval-required'
      ) {
        continue;
      }
      const name =
        tp.toolName ??
        (tp.type.startsWith('tool-')
          ? tp.type.slice('tool-'.length)
          : 'tool');
      if (!tp.toolCallId) continue;
      out.push({
        toolCallId: tp.toolCallId,
        toolName: name,
        input: tp.input ?? {},
      });
    }
  }
  return out;
}

function ApprovalCard({
  request,
  onApprove,
  onReject,
}: {
  request: PendingApproval;
  onApprove: () => void;
  onReject: () => void;
}) {
  return (
    <div className="rounded border border-amber-300 bg-amber-50 p-2 text-xs">
      <div className="font-medium text-amber-900">
        Approve <span className="font-mono">{request.toolName}</span>?
      </div>
      <pre className="mt-1 max-h-32 overflow-auto rounded bg-white px-2 py-1 font-mono text-[11px] text-gray-800">
        {JSON.stringify(request.input, null, 2)}
      </pre>
      <div className="mt-1.5 flex gap-2">
        <button
          type="button"
          onClick={onApprove}
          className="rounded bg-amber-600 px-2 py-0.5 text-white hover:bg-amber-700"
        >
          Approve
        </button>
        <button
          type="button"
          onClick={onReject}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
        >
          Reject
        </button>
      </div>
    </div>
  );
}

function PartView({ part }: { part: UIMessage['parts'][number] }) {
  if (part.type === 'text') {
    return <span className="whitespace-pre-wrap">{part.text}</span>;
  }
  // Tool parts in v6 carry a type like `tool-<name>` (well-known
  // tools registered statically) OR `dynamic-tool` (anything else,
  // including our server-defined names that weren't pre-registered
  // on the client). We handle both as a small "the assistant did X"
  // tag rather than render every result inline — the conversation
  // text usually summarizes anyway.
  if (
    part.type === 'dynamic-tool' ||
    (typeof part.type === 'string' && part.type.startsWith('tool-'))
  ) {
    // The shape is part-state-dependent; cast to a permissive view
    // for the inline label and skip if it'd be too noisy.
    const tp = part as unknown as {
      type: string;
      toolName?: string;
      state?: string;
      output?: unknown;
      errorText?: string;
    };
    const name =
      tp.toolName ??
      (tp.type.startsWith('tool-') ? tp.type.slice('tool-'.length) : 'tool');
    let suffix = '';
    if (tp.state === 'output-available') suffix = '✓';
    else if (tp.state === 'output-error' || tp.errorText) suffix = '⚠';
    else suffix = '…';
    return (
      <div className="my-1 inline-block rounded border border-gray-200 bg-white px-2 py-0.5 text-[11px] font-mono text-gray-600">
        {name} {suffix}
      </div>
    );
  }
  return null;
}
