import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it } from 'vitest';
import type { Session } from '@/lib/api';
import { OwnerLink } from './OwnerLink';
import { mayListUser } from '@/lib/users';

function renderAs(session: Session, owner: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['session'], session);
  return render(
    <QueryClientProvider client={client}>
      <OwnerLink owner={owner} />
    </QueryClientProvider>,
  );
}

describe('OwnerLink', () => {
  it('links an administrator to the owner\'s listing', () => {
    renderAs({ authenticated: true, username: 'admin', is_admin: true }, 'alice');
    expect(screen.getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/users/alice');
  });

  it('links a user to their own listing, whatever the domain on their identity', () => {
    renderAs({ authenticated: true, username: 'alice@example.org', is_admin: false }, 'alice');
    expect(screen.getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/users/alice');
  });

  it('leaves someone else\'s name as text for a user who cannot see their jobs', () => {
    renderAs({ authenticated: true, username: 'bob', is_admin: false }, 'alice');
    expect(screen.queryByRole('link')).toBeNull();
    expect(screen.getByText('alice')).toBeTruthy();
  });
});

describe('mayListUser', () => {
  it('says no before the session is known', () => {
    expect(mayListUser('alice', undefined)).toBe(false);
  });
});
