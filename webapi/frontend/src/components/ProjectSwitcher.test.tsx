import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';

const setProject = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: { ...actual.api, placement: { ...actual.api.placement, setProject: (p: string) => setProject(p) } },
  };
});

async function renderSwitcher(projects: string[], project?: string) {
  const { ProjectSwitcher } = await import('./ProjectSwitcher');
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ProjectSwitcher projects={projects} project={project} />
    </QueryClientProvider>,
  );
}

describe('ProjectSwitcher', () => {
  it('selects another project', async () => {
    setProject.mockResolvedValue({ project: 'ProjB' });
    await renderSwitcher(['ProjA', 'ProjB'], 'ProjA');
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ProjB' } });
    await waitFor(() => expect(setProject).toHaveBeenCalledWith('ProjB'));
  });

  it('is absent with one project', async () => {
    await renderSwitcher(['ProjA']);
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  });
});
