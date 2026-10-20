import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PlacementMyRequestState } from '@/lib/api';

const myRequest = vi.fn();
const requestAccess = vi.fn();
const withdrawRequest = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      placement: {
        ...actual.api.placement,
        myRequest: (...a: unknown[]) => myRequest(...a),
        requestAccess: (...a: unknown[]) => requestAccess(...a),
        withdrawRequest: (...a: unknown[]) => withdrawRequest(...a),
      },
    },
  };
});

const { PlacementAccessRequest, addProject, MAX_PROJECTS } = await import('./PlacementAccessRequest');

const none: PlacementMyRequestState = {
  identity: 'newbie@idp.example',
  display_name: 'New Bie',
  email: 'newbie@example.edu',
  request: null,
};

function withRequest(r: Partial<NonNullable<PlacementMyRequestState['request']>>): PlacementMyRequestState {
  return {
    ...none,
    request: {
      id: 4,
      status: 'pending',
      projects: ['Physics'],
      note: 'PhD student',
      created_at: '2026-10-17T12:00:00Z',
      updated_at: '2026-10-17T12:00:00Z',
      ...r,
    },
  };
}

function renderIt(onApproved = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <PlacementAccessRequest onApproved={onApproved} />
    </QueryClientProvider>,
  );
  return onApproved;
}

describe('PlacementAccessRequest', () => {
  beforeEach(() => {
    myRequest.mockReset();
    requestAccess.mockReset();
    withdrawRequest.mockReset();
  });

  it('files a request with the projects typed as tags and a note', async () => {
    myRequest.mockResolvedValue(none);
    requestAccess.mockResolvedValue(withRequest({ projects: ['Physics', 'Chemistry'], note: 'hi' }));
    renderIt();

    const form = await screen.findByRole('region', { name: 'Request access' });
    // Who the request is from, as the provider gave it.
    expect(within(form).getByText('newbie@idp.example')).toBeInTheDocument();
    expect(within(form).getByText('New Bie')).toBeInTheDocument();
    expect(within(form).getByText('newbie@example.edu')).toBeInTheDocument();

    const input = within(form).getByLabelText('Projects');
    fireEvent.change(input, { target: { value: 'Physics' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    // A comma ends a project too; a repeat (any case) is dropped.
    fireEvent.change(input, { target: { value: 'physics,Chemistry,' } });
    expect(within(form).getByRole('list', { name: 'Requested projects' }).textContent).toBe('Physics×Chemistry×');
    fireEvent.change(input, { target: { value: 'Biology' } });
    fireEvent.click(within(form).getByRole('button', { name: 'Remove Chemistry' }));
    fireEvent.change(within(form).getByLabelText('Note (optional)'), { target: { value: 'hi' } });
    fireEvent.click(within(form).getByRole('button', { name: 'Request access' }));

    await waitFor(() => expect(requestAccess).toHaveBeenCalledTimes(1));
    // What was still being typed is included.
    expect(requestAccess.mock.calls[0][0]).toEqual({ projects: ['Physics', 'Biology'], note: 'hi' });
    expect(await screen.findByRole('region', { name: 'Access requested' })).toBeInTheDocument();
  });

  it('shows a pending request and withdraws it', async () => {
    myRequest.mockResolvedValue(withRequest({ note: '<b>not bold</b>' }));
    withdrawRequest.mockResolvedValue(withRequest({ status: 'withdrawn' }));
    renderIt();

    const pending = await screen.findByRole('region', { name: 'Access requested' });
    expect(within(pending).getByText('Your request is waiting for an administrator.')).toBeInTheDocument();
    // Text, not markup.
    expect(within(pending).getByText('<b>not bold</b>')).toBeInTheDocument();
    expect(pending.querySelector('b')).toBeNull();

    fireEvent.click(within(pending).getByRole('button', { name: 'Withdraw request' }));
    await waitFor(() => expect(withdrawRequest).toHaveBeenCalledTimes(1));
    const form = await screen.findByRole('region', { name: 'Request access' });
    expect(within(form).getByText('You withdrew your last request.')).toBeInTheDocument();
  });

  it("shows a denial with the administrator's reason, and lets them ask again", async () => {
    myRequest.mockResolvedValue(
      withRequest({ status: 'denied', reason: 'Ask your PI.', decided_at: '2026-10-18T09:00:00Z' }),
    );
    renderIt();

    const denied = await screen.findByRole('region', { name: 'Access denied' });
    expect(within(denied).getByText('Ask your PI.')).toBeInTheDocument();
    fireEvent.click(within(denied).getByRole('button', { name: 'Request again' }));
    expect(await screen.findByRole('region', { name: 'Request access' })).toBeInTheDocument();
  });

  it('tells the page once when the request is approved', async () => {
    myRequest.mockResolvedValue(withRequest({ status: 'approved', account: 'newbie@ap.example' }));
    const onApproved = renderIt();

    const approved = await screen.findByRole('region', { name: 'Access approved' });
    expect(within(approved).getByText('newbie@ap.example')).toBeInTheDocument();
    await waitFor(() => expect(onApproved).toHaveBeenCalledTimes(1));
  });

  it('shows why a request was refused', async () => {
    myRequest.mockResolvedValue(none);
    const { ApiError } = await import('@/lib/api');
    requestAccess.mockRejectedValue(new ApiError(409, 'You already have a pending request.'));
    renderIt();
    const form = await screen.findByRole('region', { name: 'Request access' });
    fireEvent.click(within(form).getByRole('button', { name: 'Request access' }));
    expect(await within(form).findByText('You already have a pending request.')).toBeInTheDocument();
  });
});

describe('addProject', () => {
  it('trims, drops blanks and repeats, and stops at the limit', () => {
    expect(addProject([], '  Physics ')).toEqual(['Physics']);
    expect(addProject(['Physics'], 'PHYSICS')).toEqual(['Physics']);
    expect(addProject(['Physics'], '   ')).toEqual(['Physics']);
    const full = Array.from({ length: MAX_PROJECTS }, (_, i) => `p${i}`);
    expect(addProject(full, 'one-more')).toBe(full);
    expect(addProject([], 'x'.repeat(80))[0]).toHaveLength(64);
  });
});
