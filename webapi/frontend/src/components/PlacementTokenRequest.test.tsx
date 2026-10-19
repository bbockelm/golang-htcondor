import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, type PlacementIssued, type PlacementMe } from '@/lib/api';

const me = vi.fn();
const requestToken = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      placement: {
        ...actual.api.placement,
        me: (...a: unknown[]) => me(...a),
        requestToken: (...a: unknown[]) => requestToken(...a),
      },
    },
  };
});

const alice: PlacementMe = {
  identity: 'alice@idp.example',
  display_name: 'Alice',
  authorized: true,
  expired: false,
  account: 'alice@ap.example',
  authorizations: [
    { name: 'READ', label: 'Read', color: 'normal', description: 'Read jobs' },
    { name: 'WRITE', label: 'Write', color: 'warning', description: 'Submit jobs' },
  ],
  projects: [
    { name: 'ProjA', default: true, enabled: false },
    { name: 'ProjB', default: false, enabled: true },
  ],
  account_enabled: false,
  records_available: true,
};

async function renderForm(userCode?: string, onIssued = vi.fn()) {
  const { PlacementTokenRequest } = await import('./PlacementTokenRequest');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <PlacementTokenRequest userCode={userCode} onIssued={onIssued} />
    </QueryClientProvider>,
  );
  return onIssued;
}

describe('PlacementTokenRequest', () => {
  beforeEach(() => {
    me.mockReset();
    requestToken.mockReset();
  });

  it('offers the projects and permissions and requests a token', async () => {
    me.mockResolvedValue(alice);
    const issued: PlacementIssued = { token: 't', project: 'ProjB', authorizations: ['READ', 'WRITE'] };
    requestToken.mockResolvedValue(issued);
    const onIssued = await renderForm();

    expect(await screen.findByText('Read: Read jobs')).toBeInTheDocument();
    expect(screen.getByText('Write: Submit jobs')).toHaveClass('text-amber-700');
    // A disabled project cannot be chosen; the first enabled one is.
    expect(screen.getByRole('option', { name: 'ProjA (disabled)' })).toBeDisabled();
    expect(screen.getByRole('combobox')).toHaveValue('ProjB');
    expect(screen.getByRole('alert')).toHaveTextContent('not currently allowed to place jobs');

    fireEvent.click(screen.getByRole('button', { name: 'Request token' }));
    await waitFor(() => expect(onIssued).toHaveBeenCalled());
    // Nothing in the request names a user: the server uses the session's.
    expect(requestToken).toHaveBeenCalledWith({ project: 'ProjB', authorizations: ['READ', 'WRITE'] });
  });

  it('binds the token to a device request', async () => {
    me.mockResolvedValue({ ...alice, account_enabled: true });
    requestToken.mockResolvedValue({ project: 'ProjB', authorizations: ['READ'] });
    await renderForm('BCDF-GHJK');
    fireEvent.click(await screen.findByText('Write: Submit jobs'));
    fireEvent.click(screen.getByRole('button', { name: 'Request token' }));
    await waitFor(() =>
      expect(requestToken).toHaveBeenCalledWith({
        project: 'ProjB',
        authorizations: ['READ'],
        user_code: 'BCDF-GHJK',
      }),
    );
  });

  it('says so when the identity is not authorized', async () => {
    me.mockResolvedValue({ ...alice, authorized: false, authorizations: [], projects: [] });
    await renderForm();
    expect(await screen.findByText(/is not authorized to use this access point/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Request token' })).not.toBeInTheDocument();
  });

  it('says plainly that placement is unavailable', async () => {
    me.mockRejectedValue(new ApiError(503, 'Placement tokens are not available on this server.'));
    await renderForm();
    expect(
      await screen.findByText(
        'Placement tokens are not available on this access point right now. Please try again later.',
      ),
    ).toBeInTheDocument();
  });

  it('never shows a server failure as sent', async () => {
    // What an older server sent: the daemon's address and this server's
    // identity, which are not the person's business.
    me.mockRejectedValue(
      new ApiError(
        502,
        'Failed to look up your placement identity: failed to connect to placementd at <128.105.76.18:9618?sock=placementd_7607_5906>: command 556 refused by the peer (DENIED)',
      ),
    );
    await renderForm();
    expect(
      await screen.findByText('Your placement details could not be loaded. Please try again later.'),
    ).toBeInTheDocument();
    expect(screen.queryByText(/placementd|DENIED|128\.105/)).not.toBeInTheDocument();
  });

  it('shows a plain message when the token request fails', async () => {
    me.mockResolvedValue({ ...alice, account_enabled: true });
    requestToken.mockRejectedValue(new ApiError(502, 'Failed to issue a token: refused by the peer (DENIED)'));
    await renderForm();
    fireEvent.click(await screen.findByRole('button', { name: 'Request token' }));
    expect(
      await screen.findByText('The token could not be issued. Please try again later.'),
    ).toBeInTheDocument();
    expect(screen.queryByText(/DENIED/)).not.toBeInTheDocument();
  });

  it('says so when the mapping has expired', async () => {
    me.mockResolvedValue({ ...alice, authorized: false, expired: true });
    await renderForm();
    expect(await screen.findByText(/has expired on this access point/)).toBeInTheDocument();
  });
});

describe('splitAPUserID', () => {
  it('splits at the first @', async () => {
    const { splitAPUserID } = await import('./PlacementTokenRequest');
    expect(splitAPUserID('alice@ap.example')).toEqual(['alice', 'ap.example']);
    expect(splitAPUserID('alice')).toEqual(['alice', '']);
    expect(splitAPUserID(undefined)).toEqual(['', '']);
  });
});
