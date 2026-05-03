import JupyterDetailClient from './JupyterDetailClient';

// Required for Next.js static export. We emit a single placeholder; the
// Go-side SPA handler resolves any /interactive/jupyter/<id> URL to this
// page, and the client picks up the real ID via useResolvedParams.
export function generateStaticParams() {
  return [{ id: '_' }];
}

export default function Page() {
  return <JupyterDetailClient />;
}
