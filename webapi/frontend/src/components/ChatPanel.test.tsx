import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatScope } from '@/lib/api';
import { ChatPanel } from './ChatPanel';

// The panel sends the page's scope with every request, says which jobs
// the assistant sees from the server's resolution of that scope (never
// from a constant), and names the owner on an approval card when the
// server says the job is somebody else's.

const chatScope = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      chat: { ...actual.api.chat, scope: (...a: unknown[]) => chatScope(...a) },
    },
  };
});

// sse frames UI-message-stream chunks the way the server's chat.Writer
// does.
function sse(chunks: object[]): Response {
  const body = chunks.map((c) => `data: ${JSON.stringify(c)}\n\n`).join('');
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream', 'x-vercel-ai-ui-message-stream': 'v1' },
  });
}

const fetchMock = vi.fn();

function renderPanel(props: Partial<React.ComponentProps<typeof ChatPanel>> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <ChatPanel visible page="jobs" defaultOpen {...props} />
    </QueryClientProvider>,
  );
}

async function send(text: string) {
  fireEvent.change(screen.getByPlaceholderText('Ask the assistant…'), { target: { value: text } });
  fireEvent.click(screen.getByRole('button', { name: 'Send' }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
}

function requestBody(): Record<string, unknown> {
  const init = fetchMock.mock.calls[0][1] as RequestInit;
  return JSON.parse(String(init.body));
}

const resolved = (r: Partial<ChatScope>): ChatScope => ({
  requested: 'mine',
  scope: 'mine',
  act_on_others: false,
  ...r,
});

describe('ChatPanel scope', () => {
  beforeEach(() => {
    chatScope.mockReset();
    fetchMock.mockReset();
    fetchMock.mockResolvedValue(sse([{ type: 'start-step' }, { type: 'finish-step' }]));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends the scope prop with the request', async () => {
    chatScope.mockResolvedValue(resolved({ requested: 'everyone', scope: 'everyone' }));
    renderPanel({ scope: 'everyone' });
    await send('whose jobs are held?');
    expect(requestBody()).toMatchObject({ page: 'jobs', scope: 'everyone' });
  });

  it('sends mine when the page has no scope', async () => {
    chatScope.mockResolvedValue(resolved({}));
    renderPanel({ page: 'submit' });
    await send('hello');
    expect(requestBody()).toMatchObject({ page: 'submit', scope: 'mine' });
  });

  it("says the assistant sees every user's jobs when the server resolved everyone", async () => {
    chatScope.mockResolvedValue(resolved({ requested: 'everyone', scope: 'everyone', act_on_others: true }));
    renderPanel({ scope: 'everyone' });
    expect(await screen.findByTestId('chat-scope-notice')).toHaveTextContent("The assistant sees every user's jobs.");
    expect(chatScope).toHaveBeenCalledWith('jobs', 'everyone');
  });

  it('says own jobs are all it can see when everyone was asked for and refused', async () => {
    chatScope.mockResolvedValue(resolved({ requested: 'everyone', scope: 'mine' }));
    renderPanel({ scope: 'everyone' });
    expect(await screen.findByTestId('chat-scope-notice')).toHaveTextContent('Your own jobs are all the assistant can see.');
    expect(screen.queryByText(/every user's jobs/)).toBeNull();
  });

  it('says only own jobs in the mine view', async () => {
    chatScope.mockResolvedValue(resolved({}));
    renderPanel();
    expect(await screen.findByTestId('chat-scope-notice')).toHaveTextContent('The assistant only sees your own jobs.');
  });

  it("says a lead sees their projects' jobs", async () => {
    chatScope.mockResolvedValue(resolved({ requested: 'everyone', scope: 'projects', projects: ['astro'] }));
    renderPanel({ scope: 'everyone' });
    expect(await screen.findByTestId('chat-scope-notice')).toHaveTextContent(
      'The assistant sees your jobs and those of the projects you lead.',
    );
  });

  it("names the owner on an approval card for another user's job, and offers no auto-approve", async () => {
    chatScope.mockResolvedValue(resolved({ requested: 'everyone', scope: 'everyone', act_on_others: true }));
    fetchMock.mockResolvedValue(
      sse([
        { type: 'start-step' },
        { type: 'tool-input-start', toolCallId: 'tu_1', toolName: 'hold_job', providerExecuted: true },
        {
          type: 'tool-input-available',
          toolCallId: 'tu_1',
          toolName: 'hold_job',
          input: { cluster_id: 2, proc_id: 0 },
          providerExecuted: true,
        },
        { type: 'tool-approval-request', approvalId: 'tu_1', toolCallId: 'tu_1', approvalDescriptor: { owners: ['bob'] } },
        { type: 'finish-step' },
      ]),
    );
    renderPanel({ scope: 'everyone' });
    await screen.findByTestId('chat-scope-notice');
    await send('hold 2.0');
    expect(await screen.findByText('Owner: bob')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'More approve options' })).toBeNull();
  });

  it('shows no owner line when the server sent none', async () => {
    chatScope.mockResolvedValue(resolved({}));
    fetchMock.mockResolvedValue(
      sse([
        { type: 'start-step' },
        { type: 'tool-input-start', toolCallId: 'tu_1', toolName: 'hold_job', providerExecuted: true },
        {
          type: 'tool-input-available',
          toolCallId: 'tu_1',
          toolName: 'hold_job',
          input: { cluster_id: 3, proc_id: 0 },
          providerExecuted: true,
        },
        { type: 'tool-approval-request', approvalId: 'tu_1', toolCallId: 'tu_1' },
        { type: 'finish-step' },
      ]),
    );
    renderPanel();
    await screen.findByTestId('chat-scope-notice');
    await send('hold 3.0');
    expect(await screen.findByText(/Approve/, { selector: 'div' })).toBeInTheDocument();
    expect(screen.queryByText(/^Owners?:/)).toBeNull();
    expect(screen.getByRole('button', { name: 'More approve options' })).toBeInTheDocument();
  });
});
