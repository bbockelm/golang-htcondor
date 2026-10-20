import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  AccessRequest,
  AccessRequestList,
  DirAccount,
  DirAuthorization,
  DirProject,
  PlacementKind,
} from '@/lib/placementAdmin';

const requests = vi.fn();
const list = vi.fn();
const approveRequest = vi.fn();
const denyRequest = vi.fn();
const resolveRequest = vi.fn();
const batch = vi.fn();

vi.mock('@/lib/placementAdmin', async () => {
  const actual = await vi.importActual<typeof import('@/lib/placementAdmin')>('@/lib/placementAdmin');
  return {
    ...actual,
    placementAdmin: {
      ...actual.placementAdmin,
      requests: (...a: unknown[]) => requests(...a),
      list: (...a: unknown[]) => list(...a),
      approveRequest: (...a: unknown[]) => approveRequest(...a),
      denyRequest: (...a: unknown[]) => denyRequest(...a),
      resolveRequest: (...a: unknown[]) => resolveRequest(...a),
      batch: (...a: unknown[]) => batch(...a),
    },
  };
});

const { PlacementAdminError } = await import('@/lib/placementAdmin');
const { Requests, approvalStart } = await import('./Requests');

const newbie: AccessRequest = {
  id: 7,
  identity: 'newbie@idp.example',
  display_name: '<img src=x onerror=alert(1)>',
  email: 'newbie@example.edu',
  projects: ['physics', 'Chemistry'],
  note: '<script>alert(1)</script>',
  status: 'pending',
  created_at: '2026-10-17T12:00:00Z',
  updated_at: '2026-10-17T12:00:00Z',
  suggested_account: 'newbie@ap.example',
};

const authorizations: DirAuthorization[] = [
  { id: 'z1', source: 'mapfile', version: 1, name: 'READ', label: 'Read', requestable: true },
  { id: 'z2', source: 'mapfile', version: 1, name: 'WRITE', label: 'Write', requestable: true },
  { id: 'z3', source: 'mapfile', version: 1, name: 'INSTRUCTOR', label: 'Instructor', requestable: false },
];
const projects: DirProject[] = [
  { id: 'p1', source: 'internal', version: 1, name: 'Physics', accounts: [] },
  { id: 'p2', source: 'internal', version: 1, name: 'Staff', accounts: [] },
];
const accounts: DirAccount[] = [];

function listing(over: Partial<AccessRequestList> = {}): AccessRequestList {
  return { requests: [newbie], pending: 1, can_approve: true, ...over };
}

function renderRequests() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Requests />
    </QueryClientProvider>,
  );
}

async function openApproval() {
  renderRequests();
  const row = await screen.findByTestId('request-row-7');
  const approve = within(row).getByRole('button', { name: 'Approve' });
  await waitFor(() => expect(approve).toBeEnabled());
  fireEvent.click(approve);
  return screen.findByRole('dialog', { name: 'Approve access request' });
}

describe('Requests', () => {
  beforeEach(() => {
    for (const m of [requests, list, approveRequest, denyRequest, resolveRequest, batch]) m.mockReset();
    requests.mockResolvedValue(listing());
    list.mockImplementation(async (kind: PlacementKind) =>
      ({ authorizations, projects, accounts, identities: [] })[kind],
    );
  });

  it('lists pending requests, rendering what the requester typed as text', async () => {
    renderRequests();
    const row = await screen.findByTestId('request-row-7');
    expect(requests).toHaveBeenCalledWith('pending');
    expect(within(row).getByText('newbie@idp.example')).toBeInTheDocument();
    expect(within(row).getByText('newbie@example.edu')).toBeInTheDocument();
    expect(within(row).getByText('<script>alert(1)</script>')).toBeInTheDocument();
    expect(within(row).getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(row.querySelector('script, img')).toBeNull();

    fireEvent.click(screen.getByRole('tab', { name: 'All' }));
    await waitFor(() => expect(requests).toHaveBeenCalledWith('all'));
  });

  it('is read-only without directory management', async () => {
    requests.mockResolvedValue(listing({ can_approve: false }));
    renderRequests();
    const row = await screen.findByTestId('request-row-7');
    expect(within(row).queryByRole('button', { name: 'Approve' })).toBeNull();
    expect(within(row).queryByRole('button', { name: 'Deny' })).toBeNull();
    expect(screen.getByText(/requests are read-only here/)).toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
  });

  it('approves through the Onboard user form, pre-filled from the request', async () => {
    approveRequest.mockResolvedValue({ committed: true, dry_run: false, results: [] });
    const dialog = await openApproval();

    const identity = within(dialog).getByLabelText('Identity') as HTMLInputElement;
    expect(identity.value).toBe('newbie@idp.example');
    expect(identity.readOnly).toBe(true);
    expect(within(dialog).getByLabelText(/^Account/)).toHaveValue('newbie@ap.example');
    expect(within(dialog).getByLabelText('Display name')).toHaveValue('<img src=x onerror=alert(1)>');
    expect(within(dialog).getByRole('checkbox', { name: 'Read' })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: 'Write' })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: 'Instructor' })).not.toBeChecked();
    // "physics" matched the directory's Physics; Chemistry is not there.
    expect(within(dialog).getByRole('checkbox', { name: 'Physics' })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: 'Staff' })).not.toBeChecked();
    expect(within(dialog).getByText('Chemistry')).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Default project')).toHaveValue('Physics');

    fireEvent.change(within(dialog).getByLabelText('Change comment (optional)'), { target: { value: 'welcome' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(approveRequest).toHaveBeenCalledTimes(1));
    expect(approveRequest.mock.calls[0]).toEqual([
      7,
      {
        account: 'newbie@ap.example',
        authorizations: ['READ', 'WRITE'],
        projects: ['Physics'],
        default_project: 'Physics',
        expires_at: null,
        display_name: '<img src=x onerror=alert(1)>',
        comment: 'welcome',
      },
      false,
    ]);
    // Nothing went through the generic batch endpoint.
    expect(batch).not.toHaveBeenCalled();
    expect(await screen.findByText('Request approved.')).toBeInTheDocument();
  });

  it('checks an approval as a dry run', async () => {
    approveRequest.mockResolvedValue({ committed: false, dry_run: true, results: [] });
    const dialog = await openApproval();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Check' }));
    await waitFor(() => expect(approveRequest).toHaveBeenCalledTimes(1));
    expect(approveRequest.mock.calls[0][2]).toBe(true);
    expect(await within(dialog).findByText('No problems found.')).toBeInTheDocument();
  });

  it('offers to mark the request resolved when the identity already exists', async () => {
    approveRequest.mockRejectedValue(
      new PlacementAdminError(409, 'The identity newbie@idp.example is already in the directory.', {
        identity_exists: true,
      }),
    );
    resolveRequest.mockResolvedValue({ ...newbie, status: 'approved' });
    const dialog = await openApproval();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    const resolve = await within(dialog).findByRole('button', { name: 'mark the request resolved' });
    fireEvent.click(resolve);
    await waitFor(() => expect(resolveRequest).toHaveBeenCalledWith(7));
    expect(await screen.findByText('Request marked resolved.')).toBeInTheDocument();
  });

  it('denies with a reason', async () => {
    denyRequest.mockResolvedValue({ ...newbie, status: 'denied' });
    renderRequests();
    const row = await screen.findByTestId('request-row-7');
    fireEvent.click(within(row).getByRole('button', { name: 'Deny' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deny access request' });
    const deny = within(dialog).getByRole('button', { name: 'Deny' });
    expect(deny).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Reason (shown to the requester)'), {
      target: { value: '  Ask your PI.  ' },
    });
    fireEvent.click(deny);
    await waitFor(() => expect(denyRequest).toHaveBeenCalledWith(7, 'Ask your PI.'));
    expect(await screen.findByText('Request denied.')).toBeInTheDocument();
  });
});

describe('approvalStart', () => {
  it('suggests the account, matches projects ignoring case, and starts with READ and WRITE', () => {
    const { initial, unknownProjects } = approvalStart(
      { ...newbie, projects: ['PHYSICS', 'physics', 'Chemistry'] },
      ['Physics', 'Staff'],
      authorizations,
    );
    expect(initial.account).toBe('newbie@ap.example');
    expect(initial.projects).toEqual(['Physics']);
    expect(initial.defaultProject).toBe('Physics');
    expect(initial.authorizations).toEqual(['READ', 'WRITE']);
    expect(unknownProjects).toEqual(['Chemistry']);
  });

  it('starts with no authorizations the directory lacks', () => {
    const { initial } = approvalStart(newbie, [], [authorizations[0]]);
    expect(initial.authorizations).toEqual(['READ']);
    expect(initial.projects).toEqual([]);
    expect(initial.defaultProject).toBe('');
  });
});
