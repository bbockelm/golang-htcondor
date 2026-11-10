import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it } from 'vitest';
import { SuperuserBanner } from './SuperuserBanner';
import type { Session } from '@/lib/api';

function banner(session: Partial<Session>) {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <SuperuserBanner session={{ authenticated: true, is_admin: false, ...session }} />
    </QueryClientProvider>,
  );
}

describe('SuperuserBanner', () => {
  it('names the projects a project lead may act in', () => {
    banner({ superuser_active: true, superuser_scope: 'project', superuser_projects: ['Chem', 'Physics'] });
    expect(screen.getByText('Project lead mode')).toBeInTheDocument();
    expect(screen.getByText('Chem, Physics')).toBeInTheDocument();
  });

  it('keeps the global wording for a global superuser', () => {
    banner({ superuser_active: true, superuser_scope: 'global' });
    expect(screen.getByText('Superuser mode')).toBeInTheDocument();
    expect(screen.queryByText('Project lead mode')).not.toBeInTheDocument();
  });

  it('renders nothing while disarmed', () => {
    const { container } = banner({ superuser_active: false });
    expect(container).toBeEmptyDOMElement();
  });
});
