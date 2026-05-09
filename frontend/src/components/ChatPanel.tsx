'use client';

// LLM-backed chat panel, reusable across SPA pages.
//
// The panel itself is page-agnostic. Each host page passes:
//   - `page` — short identifier sent to the server so the engine
//     selects the matching system-prompt suffix and tool subset
//     (e.g. "jobs", "submit"). The string must match a key the
//     server knows; see chatPageInstructions() in
//     httpserver/handlers_chat_tools.go.
//   - `hooks` — table of client-side tool dispatchers, keyed by
//     tool name. The panel looks up the entry by toolName when the
//     LLM emits a tool_use; if the entry returns a value, that
//     value becomes the tool_result output (a `void` return is
//     treated as `{ ok: true }`). Throwing reports an error.
//   - `confirmableTools` — names of tools that require an
//     auto-approve checkbox (jobs page lists hold/release/remove;
//     submit page passes an empty list and the row hides).
//   - `pageHelp`, `togglerLabel`, `headerLabel` — host-supplied UI
//     strings so each page can phrase its empty-state hint and
//     pill label appropriately.
//
// All chat-streaming, tool dispatch, approval-card UI, and
// auto-approve persistence live here once and don't need to be
// reimplemented on a new page.

import { useChat } from '@ai-sdk/react';
import {
  DefaultChatTransport,
  lastAssistantMessageIsCompleteWithApprovalResponses,
  lastAssistantMessageIsCompleteWithToolCalls,
  type UIMessage,
} from 'ai';
import dynamic from 'next/dynamic';
import remarkGfm from 'remark-gfm';

// react-markdown is ESM-only; importing it eagerly trips Next.js
// static export's prerender. We're inside a `'use client'` file but
// static export still tries to walk the module graph during build,
// so defer the load to the client and skip SSR entirely.
const ReactMarkdown = dynamic(() => import('react-markdown'), { ssr: false });
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '@/lib/api';

const AUTO_APPROVE_LS_KEY = 'htcondor-api.chat.auto_approve';

// ToolHandler is the per-page client-side dispatcher signature. The
// panel calls `hooks[toolName](input)` when the LLM invokes a
// client-side tool. Return value semantics:
//   - `undefined` → panel sends `{ ok: true }` as the tool result
//   - any other value → sent as-is (will be JSON-serialized)
//   - thrown error → panel sends an `{ ok: false, error: ... }`
//
// Pages that need to refuse a call can return `{ ok: false, error: '...' }`.
export type ToolHandler = (input: Record<string, unknown>) => unknown;

// loadAutoApprove pulls the persisted auto-approve set from
// localStorage. Per-browser, per-user — we don't sync across tabs/
// devices because operator override of the confirmation gate is
// exactly the kind of decision that should re-trigger when the user
// moves to a new machine. Validates against the supplied allowlist
// so a tool removal can't leave a stale entry hot in storage.
function loadAutoApprove(allowed: readonly string[]): Set<string> {
  if (typeof window === 'undefined') return new Set();
  try {
    const raw = window.localStorage.getItem(AUTO_APPROVE_LS_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) return new Set();
    return new Set(
      arr.filter((x): x is string => typeof x === 'string' && allowed.includes(x)),
    );
  } catch {
    return new Set();
  }
}

function saveAutoApprove(set: Set<string>) {
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

interface ChatPanelProps {
  // Whether the parent has decided the chat is allowed to render.
  // When false the component returns null — the host page typically
  // hides via a wrapper too, but this guard keeps a misuse from
  // blowing up the page.
  visible: boolean;
  // SPA page identifier sent to the server with each request. Drives
  // tool filtering and per-page system-prompt suffix selection.
  page: string;
  // Optional free-form per-request context the host page wants the
  // LLM to know about — e.g. on the per-job page, the cluster.proc
  // id, current job status, last host. Appended to the system prompt
  // so the LLM doesn't have to ask "which job?" on every turn.
  // Pure metadata; the server caps the length and never feeds it into
  // any tool input.
  pageContext?: string;
  // Client-side tool dispatchers, keyed by tool name. Entries the
  // server doesn't advertise for the current page never get called;
  // a missing entry for a tool the LLM somehow invoked falls through
  // to an "unknown tool" error.
  hooks?: Record<string, ToolHandler>;
  // Tool names that should appear as auto-approve checkboxes. Empty
  // hides the row entirely. Defaults to the jobs-page set for back-
  // compat with callers that omit the prop.
  confirmableTools?: readonly string[];
  // Empty-state placeholder shown when there are no messages.
  pageHelp?: string;
  // Pill text shown when the panel is collapsed.
  togglerLabel?: string;
  // Title shown in the panel header when expanded.
  headerLabel?: string;
  // Whether to render the panel expanded on first mount. Defaults to
  // false (the user sees a "Ask the assistant" pill until they click).
  // Pages where the assistant is the *primary* affordance — e.g. the
  // submit page where the agent is intended to scaffold the job for
  // first-time users — should pass true so it's visible by default.
  defaultOpen?: boolean;
  // Fires when a server-executed tool reaches output-available (the
  // engine's resolution path emits providerExecuted=true on those).
  // Use this to invalidate any react-query data the tool mutated —
  // e.g. the jobs page invalidates ['jobs'] after remove_job /
  // hold_job / release_job so the table updates immediately instead
  // of waiting for the 15-second polling interval. The callback fires
  // exactly ONCE per toolCallId — it's fine to call expensive
  // invalidations in here without debouncing.
  onServerToolComplete?: (toolName: string, output: unknown) => void;
}

// Bulk and single-target removes are intentionally separate keys
// here. A user who's auto-approved single removes should NOT also
// auto-approve "delete every match of a constraint" — the blast
// radius is meaningfully different and the confirmation card is the
// only checkpoint between an LLM mistake and an empty queue.
const JOBS_DEFAULT_CONFIRMABLE = [
  'hold_job',
  'release_job',
  'remove_job',
  'remove_jobs',
] as const;

const DEFAULT_PAGE_HELP =
  'Ask things like "what GPUs are available?" or "scaffold a job that runs my Python script".';
const DEFAULT_TOGGLER_LABEL = 'Ask the assistant';
const DEFAULT_HEADER_LABEL = 'Assistant';

// ChatPanel is the reusable LLM chat surface. Sits below whatever
// content the host page already renders; collapses to a small pill
// until the user opens it.
export function ChatPanel({
  visible,
  page,
  pageContext,
  hooks,
  confirmableTools = JOBS_DEFAULT_CONFIRMABLE,
  pageHelp = DEFAULT_PAGE_HELP,
  togglerLabel = DEFAULT_TOGGLER_LABEL,
  headerLabel = DEFAULT_HEADER_LABEL,
  defaultOpen = false,
  onServerToolComplete,
}: ChatPanelProps) {
  // Auto-approve set + pending-approval list. Both flow into the
  // transport's body resolver via refs so the closure inside
  // DefaultChatTransport always sees the latest state without
  // having to rebuild the transport on every render.
  const [autoApprove, setAutoApprove] = useState<Set<string>>(
    () => loadAutoApprove(confirmableTools),
  );
  useEffect(() => {
    saveAutoApprove(autoApprove);
  }, [autoApprove]);

  const approvedIdsRef = useRef<string[]>([]);
  const autoApproveRef = useRef<Set<string>>(autoApprove);
  const pageRef = useRef<string>(page);
  const pageContextRef = useRef<string>(pageContext ?? '');
  // Mirror state into refs via effect so the body resolver inside
  // the (memoized) transport always sees latest values without us
  // writing to refs during render (which React's strict rules forbid).
  useEffect(() => {
    autoApproveRef.current = autoApprove;
  }, [autoApprove]);
  useEffect(() => {
    pageRef.current = page;
  }, [page]);
  useEffect(() => {
    pageContextRef.current = pageContext ?? '';
  }, [pageContext]);

  // useMemo so the transport instance is stable across re-renders.
  // The body resolver runs per-POST, so it sees the *latest* values
  // off the refs every time. The react-hooks/refs lint can't see
  // through the closure, so disable it here.
  /* eslint-disable react-hooks/refs */
  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: api.chat.streamURL,
        // Send our session cookie / bearer header just like every
        // other authenticated request.
        credentials: 'include',
        body: () => ({
          approved_tool_use_ids: approvedIdsRef.current,
          auto_approve: Array.from(autoApproveRef.current),
          page: pageRef.current,
          page_context: pageContextRef.current,
        }),
      }),
    [],
  );
  /* eslint-enable react-hooks/refs */

  // The SDK's onToolCall returns void; the tool result has to be
  // sent in via the chat helpers' addToolResult after dispatch. We
  // park addToolResult on a ref so the closure inside onToolCall
  // can reach it without an init-vs-return cycle (onToolCall is
  // initialized BEFORE the helpers are returned).
  const addToolResultRef = useRef<
    | ((opts: { tool: string; toolCallId: string; output: unknown }) => void)
    | null
  >(null);

  const handleToolCall = useMemo(
    () =>
      async ({
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
        const handler = hooks?.[toolCall.toolName];
        if (!handler) {
          reply({
            ok: false,
            error: `unknown client-side tool: ${toolCall.toolName}`,
          });
          return;
        }
        try {
          const input = (toolCall.input ?? {}) as Record<string, unknown>;
          // Await unconditionally — sync handlers (e.g. set_filter)
          // resolve immediately; async ones (fetch-backed reads) need
          // the await or we'd send the Promise object itself as the
          // tool output and the SDK would mark the tool resolved with
          // an empty payload, leaving the LLM with `{}`.
          const result = await handler(input);
          reply(result === undefined ? { ok: true } : result);
        } catch (e) {
          reply({ ok: false, error: e instanceof Error ? e.message : String(e) });
        }
      },
    [hooks],
  );

  const { messages, sendMessage, status, error, stop, addToolResult, addToolApprovalResponse } =
    useChat({
      transport,
      onToolCall: handleToolCall,
      // Auto-resubmit when the conversation is logically ready to
      // continue. We combine TWO predicates (OR-fashion):
      //
      //   - lastAssistantMessageIsCompleteWithToolCalls fires after a
      //     CLIENT-SIDE tool has been dispatched and its result added
      //     (state = output-available / output-error). Without this,
      //     every client-side tool boundary halts and the user has
      //     to type "continue".
      //
      //   - lastAssistantMessageIsCompleteWithApprovalResponses fires
      //     after the user has clicked Approve on a destructive tool;
      //     the part is in state = approval-responded and the round-
      //     trip needs to fire so the server can execute the
      //     approved tool.
      //
      // Both predicates filter to non-providerExecuted parts (so a
      // destructive tool we marked providerExecuted=true on the
      // confirmation chunk doesn't gate "is the last step done?").
      // A turn that ends with just text triggers neither predicate
      // → conversation idles, which is what we want.
      sendAutomaticallyWhen: ({ messages: msgs }) =>
        lastAssistantMessageIsCompleteWithToolCalls({ messages: msgs }) ||
        lastAssistantMessageIsCompleteWithApprovalResponses({ messages: msgs }),
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
  // call that's neither pre-approved nor auto-approved.
  const pending = useMemo(() => collectPendingApprovals(messages), [messages]);

  // Watch for server-executed tools that have just finished (state
  // transitioned to "output-available" with providerExecuted=true)
  // and notify the host page so it can invalidate any react-query
  // data the tool mutated. Without this, a chat-driven remove_job
  // takes up to one full polling interval (15s) to disappear from
  // the table; with it, the row clears as soon as the schedd RPC
  // returns. The reportedRef prevents firing twice for the same
  // toolCallId across renders.
  const reportedToolsRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (!onServerToolComplete) return;
    for (const m of messages) {
      if (m.role !== 'assistant') continue;
      for (const part of m.parts) {
        const tp = part as unknown as {
          type: string;
          toolName?: string;
          toolCallId?: string;
          state?: string;
          providerExecuted?: boolean;
          output?: unknown;
        };
        if (typeof tp.type !== 'string') continue;
        const isToolPart =
          tp.type === 'dynamic-tool' || tp.type.startsWith('tool-');
        if (!isToolPart) continue;
        if (!tp.providerExecuted) continue;
        if (tp.state !== 'output-available') continue;
        if (!tp.toolCallId || reportedToolsRef.current.has(tp.toolCallId))
          continue;
        reportedToolsRef.current.add(tp.toolCallId);
        const name =
          tp.toolName ??
          (tp.type.startsWith('tool-')
            ? tp.type.slice('tool-'.length)
            : 'tool');
        onServerToolComplete(name, tp.output);
      }
    }
  }, [messages, onServerToolComplete]);

  // Approve handler — three things happen in order:
  //   1. The toolCallId is pushed onto approvedIdsRef so the next
  //      POST's body carries `approved_tool_use_ids: [...]`. The
  //      server's resolvePendingApprovals reads that and executes the
  //      tool with proper actor scoping.
  //   2. addToolApprovalResponse({approved:true}) flips the OLD tool
  //      part's state from "approval-requested" to "approval-responded"
  //      with approval={id, approved:true}. THIS is what makes the
  //      approval card disappear — without it the part stays in
  //      approval-requested forever and our collectPendingApprovals
  //      keeps surfacing the card.
  //   3. The auto-resubmit predicate
  //      (lastAssistantMessageIsCompleteWithApprovalResponses)
  //      observes the new approval-responded state and fires a new
  //      POST automatically. We don't need to sendMessage manually.
  const approve = useCallback(
    (toolCallId: string) => {
      approvedIdsRef.current = [...approvedIdsRef.current, toolCallId];
      void addToolApprovalResponse({ id: toolCallId, approved: true });
    },
    [addToolApprovalResponse],
  );

  // Reject — mark the OLD tool part as output-available with a
  // denial result. addToolResult is the right tool here (NOT
  // addToolApprovalResponse) for two reasons:
  //   (a) The server-side resolvePendingApprovals path decides what
  //       to do based on whether the toolCallId is in `approved`.
  //       For rejection, we want it NOT to execute — leaving the id
  //       out of approvedIdsRef does that. But we ALSO need to give
  //       the LLM a tool_result so Anthropic doesn't 400 the
  //       continuation. addToolResult provides that result via the
  //       message history (state=output-available with our denial).
  //   (b) The auto-resubmit predicates filter out providerExecuted
  //       parts (we set that on the confirmation chunks), so the
  //       part transitioning to output-available does NOT trigger
  //       auto-submit. The conversation idles after rejection,
  //       which is the right UX: the user said no, and the model
  //       gets to see the denial in their next manual message
  //       (when they type something).
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

  // approveAndRemember does both an Approve AND adds the tool name to
  // the auto-approve set so future invocations of this tool skip the
  // gate. Surfaced as the secondary option on each ApprovalCard's
  // split button (the primary action is plain Approve).
  const approveAndRemember = useCallback(
    (toolCallId: string, toolName: string) => {
      setAutoApprove((prev) => {
        if (prev.has(toolName)) return prev;
        const next = new Set(prev);
        next.add(toolName);
        return next;
      });
      approvedIdsRef.current = [...approvedIdsRef.current, toolCallId];
      void addToolApprovalResponse({ id: toolCallId, approved: true });
    },
    [addToolApprovalResponse],
  );

  const [input, setInput] = useState('');
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const [open, setOpen] = useState(defaultOpen);

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
          {togglerLabel}
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
        <h2 className="text-sm font-semibold text-gray-900">{headerLabel}</h2>
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
          <p className="text-xs italic text-gray-500">{pageHelp}</p>
        )}
        {messages.map((m, i) => (
          <MessageView
            key={m.id}
            m={m}
            // Smoothing animation applies only to the in-progress
            // assistant message. We treat the LAST message as live
            // while the chat is actively streaming/submitted; once
            // it lands in 'ready' status the same render path falls
            // back to instant markdown display.
            isLive={
              i === messages.length - 1 &&
              m.role === 'assistant' &&
              (status === 'streaming' || status === 'submitted')
            }
          />
        ))}
        {pending.map((p) => (
          <ApprovalCard
            key={p.toolCallId}
            request={p}
            alreadyAuto={autoApprove.has(p.toolName)}
            onApprove={() => approve(p.toolCallId)}
            onApproveAndRemember={() => approveAndRemember(p.toolCallId, p.toolName)}
            onReject={() => reject(p.toolCallId, p.toolName)}
          />
        ))}
        {/*
          Pending indicator. Without this the user sees nothing
          between hitting Send and the first text-delta — and that gap
          can be several seconds when the model is reasoning or making
          a slow tool call. We show a pulsing "Thinking…" chip so the
          UI feels alive. The chip hides as soon as the first
          assistant content arrives (streaming text or a tool chip).
        */}
        {(status === 'submitted' || isWaitingForFirstAssistantContent(status, messages)) && (
          <div className="flex justify-start">
            <div className="inline-flex items-center gap-2 rounded bg-gray-50 px-3 py-1.5 text-sm text-gray-500">
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-gray-400" />
              <span>Thinking…</span>
            </div>
          </div>
        )}
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
            placeholder="Ask the assistant…"
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
          The assistant only sees your own jobs.
        </p>
      </div>
    </div>
  );
}

// isWaitingForFirstAssistantContent reports whether the chat is
// streaming a response but no assistant content has materialized yet
// — i.e. the model is between "we sent the request" and "first byte
// of the reply landed". Used to keep the Thinking… chip visible
// while the model is reasoning before its first token, OR while a
// long-running tool call is in flight before any text-delta. As soon
// as the latest message is from the assistant AND has at least one
// non-empty part, the chip hides.
function isWaitingForFirstAssistantContent(
  status: string,
  messages: UIMessage[],
): boolean {
  if (status !== 'streaming') return false;
  const last = messages[messages.length - 1];
  if (!last || last.role !== 'assistant') return true;
  // Streaming but the assistant message has no parts yet — still
  // pre-first-token. (An empty parts array is rare but possible
  // immediately after the SDK creates the assistant message stub.)
  if (!last.parts || last.parts.length === 0) return true;
  // Has at least one part with non-empty content — the user sees
  // SOMETHING (text delta or a tool chip) so the indicator is no
  // longer needed.
  return last.parts.every((p) => {
    if (p.type === 'text') return !p.text || p.text.trim() === '';
    return false;
  });
}

// MessageView renders one message's parts. The AI SDK packs text +
// tool calls + tool results as a heterogeneous parts array; we walk
// it and render each kind.
function MessageView({
  m,
  isLive,
}: {
  m: UIMessage;
  // True when this is the *active* assistant message — the one
  // currently being streamed/typed. Drives the per-word reveal
  // animation in PartView. Past messages render their markdown
  // directly so reload / scroll-up doesn't re-animate old text.
  isLive: boolean;
}) {
  const isUser = m.role === 'user';
  return (
    <div className={isUser ? 'flex justify-end' : 'flex justify-start'}>
      <div
        className={`max-w-[85%] rounded px-3 py-1.5 ${
          isUser ? 'bg-brand-50 text-gray-800' : 'bg-gray-50 text-gray-800'
        }`}
      >
        {m.parts.map((p, i) => (
          <PartView key={i} part={p} role={m.role} isLive={isLive} />
        ))}
      </div>
    </div>
  );
}

// PendingApproval describes one tool-use waiting for user approval.
// Constructed from the message stream — we don't keep our own list,
// we derive from messages so it stays consistent with what the SDK
// has parsed.
interface PendingApproval {
  toolCallId: string;
  toolName: string;
  input: unknown;
}

// collectPendingApprovals walks the messages and returns any tool
// parts that are awaiting approval. The SDK consumes our server's
// `tool-approval-request` chunk by transitioning the matching tool
// part to state="approval-requested" with `part.approval = { id }`
// (see ai/dist/index.mjs ~5706 and the addToolApprovalResponse API
// at ~13108). Once the user approves and the server's resolution
// path emits a tool-output-available chunk, the SDK transitions the
// part to "output-available" — we filter those out so the approval
// card disappears automatically.
//
// We DON'T look for "approval-responded" — that state is what the
// SDK writes locally when the user clicks Approve via
// addToolApprovalResponse. Our flow doesn't use that helper (we
// re-send a new turn with `approved_tool_use_ids` instead, so the
// server does the dispatch), so the part stays "approval-requested"
// until the server's tool-output-available chunk lands.
function collectPendingApprovals(messages: UIMessage[]): PendingApproval[] {
  const out: PendingApproval[] = [];
  // Dedupe by toolCallId. Without this a single toolCallId that
  // appears in two messages (e.g. once in the original assistant
  // turn, once in the SDK's working copy of the active response)
  // would render two cards. The SDK can briefly hold both during
  // streaming; the user sees overlapping approval prompts that
  // refer to the same underlying call. One id, one card.
  const seen = new Set<string>();
  for (const m of messages) {
    if (m.role !== 'assistant') continue;
    for (const part of m.parts) {
      const tp = part as unknown as {
        type: string;
        toolName?: string;
        toolCallId?: string;
        state?: string;
        input?: unknown;
        output?: unknown;
        errorText?: string;
        approval?: { id?: string };
      };
      if (typeof tp.type !== 'string') continue;
      const isToolPart =
        tp.type === 'dynamic-tool' || tp.type.startsWith('tool-');
      if (!isToolPart) continue;
      // Already resolved by output OR a user decision (approval-
      // responded means we called addToolApprovalResponse and the
      // round-trip is in flight or done). Either way: not a card.
      if (
        tp.state === 'output-available' ||
        tp.state === 'output-error' ||
        tp.state === 'approval-responded'
      ) {
        continue;
      }
      if (tp.state !== 'approval-requested') continue;
      const name =
        tp.toolName ??
        (tp.type.startsWith('tool-')
          ? tp.type.slice('tool-'.length)
          : 'tool');
      if (!tp.toolCallId) continue;
      if (seen.has(tp.toolCallId)) continue;
      seen.add(tp.toolCallId);
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
  alreadyAuto,
  onApprove,
  onApproveAndRemember,
  onReject,
}: {
  request: PendingApproval;
  // Whether the tool is already in the auto-approve set. When true,
  // the dropdown's Auto-approve item is hidden — there's nothing to
  // remember. (This shouldn't normally happen because auto-approve
  // would have skipped the gate, but a race during the initial
  // setAutoApprove → POST round-trip could land here.)
  alreadyAuto: boolean;
  onApprove: () => void;
  onApproveAndRemember: () => void;
  onReject: () => void;
}) {
  // Local dropdown state. The split button shows Approve as the
  // primary action; clicking the caret toggles a small popover with
  // an "Auto-approve" option that approves AND adds the tool name to
  // the persisted auto-approve set so future invocations skip the
  // gate. We close on outside click.
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!menuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [menuOpen]);

  return (
    <div className="rounded border border-amber-300 bg-amber-50 p-2 text-xs">
      <div className="font-medium text-amber-900">
        Approve <span className="font-mono">{request.toolName}</span>?
      </div>
      <pre className="mt-1 max-h-32 overflow-auto rounded bg-white px-2 py-1 font-mono text-[11px] text-gray-800">
        {JSON.stringify(request.input, null, 2)}
      </pre>
      <div className="mt-1.5 flex gap-2">
        {/* Split-button: primary Approve action + caret-dropdown
            for "Auto-approve <toolname>". The two halves share a
            border so they read as one control. */}
        <div className="relative inline-flex" ref={menuRef}>
          <button
            type="button"
            onClick={onApprove}
            className="rounded-l bg-amber-600 px-2 py-0.5 text-white hover:bg-amber-700"
          >
            Approve
          </button>
          {!alreadyAuto && (
            <button
              type="button"
              onClick={() => setMenuOpen((v) => !v)}
              aria-label="More approve options"
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              className="rounded-r border-l border-amber-700 bg-amber-600 px-1.5 py-0.5 text-white hover:bg-amber-700"
            >
              <span aria-hidden>▾</span>
            </button>
          )}
          {menuOpen && (
            <div
              role="menu"
              className="absolute left-0 top-full z-10 mt-1 min-w-[12rem] rounded border border-gray-200 bg-white shadow-md"
            >
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setMenuOpen(false);
                  onApproveAndRemember();
                }}
                className="block w-full px-3 py-1.5 text-left text-xs text-gray-800 hover:bg-gray-50"
              >
                <span className="font-medium">Auto-approve</span>{' '}
                <span className="font-mono text-gray-600">
                  {request.toolName}
                </span>
                <div className="text-[10px] text-gray-500">
                  Approve now and skip the prompt for future calls in
                  this browser.
                </div>
              </button>
            </div>
          )}
        </div>
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

// useTypingText reveals `target` progressively over time, advancing
// at word boundaries so partial markdown tokens (`**bo`, `[link](u`,
// triple-backtick fences) never get rendered mid-token. Speed is
// expressed in words/sec; we use FRACTIONAL accumulation across
// frames so the actual rate matches the configured wps regardless of
// rAF frequency (60 Hz, 120 Hz, etc.) — earlier I had a per-frame
// `Math.max(1, …)` floor that smuggled the rate up to 60+ wps and
// produced a "no animation visible" look.
//
// `skip=true` short-circuits the animation: the hook returns target
// directly. We use that for messages that aren't the active streaming
// turn — rerendering history shouldn't re-animate.
function useTypingText(target: string, skip: boolean): string {
  const [displayed, setDisplayed] = useState(skip ? target : '');
  const targetRef = useRef(target);
  targetRef.current = target;

  // When skip flips on (e.g. status moved from streaming → ready and
  // the message is no longer "live"), snap to the full target so the
  // user sees the complete message instantly instead of finishing the
  // animation at typewriter pace.
  useEffect(() => {
    if (skip) setDisplayed(targetRef.current);
  }, [skip]);

  useEffect(() => {
    if (skip) return;
    let canceled = false;
    let last = performance.now();
    // Fractional word counter: accumulates wps × elapsed each frame.
    // When it crosses 1.0 we reveal a whole word and subtract it,
    // carrying the remainder. Without this we'd be quantizing per
    // frame (Math.floor zero on a 16ms tick at 18 wps = 0 words →
    // a Math.max(1, …) escape would leak the rate up to 60+ wps).
    let accum = 0;
    // Local mirror of displayed.length so the rAF loop can compute
    // the backlog without re-reading React state (which would force
    // the effect into a [skip, displayed] dep, restarting the rAF
    // loop on every frame). Updated inside the setter.
    let lastDisplayedLen = 0;
    const baseWps = 18; // ~135 wpm — slower than reading speed so
    // the typing is visibly distinct from "popped in at once."

    const tick = (time: number) => {
      if (canceled) return;
      const t = targetRef.current;
      const elapsed = (time - last) / 1000;
      last = time;

      // Catch-up policy: run at base rate until we're more than 200
      // chars behind, then scale linearly so a 1000-char wall of
      // text drains in a few seconds instead of half a minute.
      // Cap at 80 wps so even huge backlogs still look like typing.
      let wps = baseWps;
      const behind = t.length - lastDisplayedLen;
      if (behind > 200) {
        wps = baseWps + (behind - 200) / 20;
        if (wps > 80) wps = 80;
      }

      accum += elapsed * wps;
      const wholeWords = Math.floor(accum);
      if (wholeWords <= 0) {
        requestAnimationFrame(tick);
        return;
      }
      accum -= wholeWords;

      setDisplayed((prev) => {
        if (prev.length >= t.length) return prev;
        const next = revealWords(t, prev.length, wholeWords);
        lastDisplayedLen = next.length;
        return next;
      });
      requestAnimationFrame(tick);
    };
    const rafID = requestAnimationFrame(tick);
    return () => {
      canceled = true;
      cancelAnimationFrame(rafID);
    };
  }, [skip]);

  return displayed;
}

// revealWords returns a prefix of `target` that ends `n` whitespace-
// delimited word boundaries past `from`. Reveals the trailing
// whitespace AFTER each word so the next word doesn't pop in
// mid-render. When `target` doesn't contain enough boundaries left,
// returns the entire string.
function revealWords(target: string, from: number, n: number): string {
  let pos = from;
  for (let i = 0; i < n && pos < target.length; i++) {
    // Skip any whitespace already at pos.
    while (pos < target.length && /\s/.test(target[pos])) pos++;
    // Advance through the next word.
    while (pos < target.length && !/\s/.test(target[pos])) pos++;
    // Include the trailing whitespace too — keeps inline layout
    // stable as words appear instead of popping margins.
    while (pos < target.length && /\s/.test(target[pos])) pos++;
  }
  return target.slice(0, pos);
}

function PartView({
  part,
  role,
  isLive,
}: {
  part: UIMessage['parts'][number];
  role: UIMessage['role'];
  isLive: boolean;
}) {
  // useTypingText must be called unconditionally on every render —
  // we always invoke it, but pass skip=true (instant render) for
  // user messages and for assistant text on inactive (history) turns.
  // This keeps hook order stable across the early returns below.
  const targetText = part.type === 'text' ? part.text : '';
  const typed = useTypingText(targetText, !isLive || role !== 'assistant');

  if (part.type === 'text') {
    // User messages are raw input the user typed — render verbatim
    // (and don't let stray markdown syntax get reinterpreted). The
    // assistant's prose, by contrast, is markdown by convention; we
    // pipe it through react-markdown + remark-gfm so bullet lists,
    // bold/italic, inline code, and tables render as the model
    // intended.
    if (role !== 'assistant') {
      return <span className="whitespace-pre-wrap">{part.text}</span>;
    }
    return (
      <div className="markdown-body">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{typed}</ReactMarkdown>
      </div>
    );
  }
  // Tool parts in v6 carry a type like `tool-<name>` (well-known
  // tools registered statically) OR `dynamic-tool` (anything else,
  // including our server-defined names that weren't pre-registered
  // on the client).
  if (
    part.type === 'dynamic-tool' ||
    (typeof part.type === 'string' && part.type.startsWith('tool-'))
  ) {
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
    // Status glyph mirrors the tool part's lifecycle. The
    // "approval-requested" state is the one easiest to confuse with
    // "still streaming" — the chip sat there with a tiny ellipsis and
    // gave no hint that the user had to act. We surface it as
    // "awaiting approval" so the user knows to look for the approval
    // card right below.
    let suffix = '';
    if (tp.state === 'output-available') suffix = '✓';
    else if (tp.state === 'output-error' || tp.errorText) suffix = '⚠';
    else if (tp.state === 'approval-requested') suffix = '— awaiting approval';
    else suffix = '…';
    return (
      <div className="my-1 inline-block rounded border border-gray-200 bg-white px-2 py-0.5 text-[11px] font-mono text-gray-600">
        {name} {suffix}
      </div>
    );
  }
  return null;
}
