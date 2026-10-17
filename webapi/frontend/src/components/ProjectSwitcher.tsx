'use client';

// ProjectSwitcher picks the project a placement-assigned account's work is
// charged to. Shown only when the account has more than one.

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function ProjectSwitcher({ projects, project }: { projects: string[]; project?: string }) {
  const qc = useQueryClient();
  const choose = useMutation({
    mutationFn: (p: string) => api.placement.setProject(p),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session'] }),
  });
  if (projects.length < 2) return null;
  return (
    <label className="mt-2 block text-[11px] text-gray-400">
      Project
      <select
        value={project ?? projects[0]}
        disabled={choose.isPending}
        onChange={(e) => choose.mutate(e.target.value)}
        className="mt-0.5 block w-full rounded-sm border border-white/10 bg-ink-950 px-1 py-0.5 text-xs text-gray-200"
      >
        {projects.map((p) => (
          <option key={p} value={p}>
            {p}
          </option>
        ))}
      </select>
      {choose.isError && (
        <span className="mt-1 block text-red-300">{(choose.error as Error).message}</span>
      )}
    </label>
  );
}
