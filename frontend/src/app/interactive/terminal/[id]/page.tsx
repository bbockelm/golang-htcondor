import TerminalDetailClient from './TerminalDetailClient';

// Required for Next.js static export. We emit a single placeholder; the
// Go-side SPA handler resolves any /interactive/terminal/<id> URL to
// this page, and the client picks up the real cluster.proc id via
// useResolvedParams.
export function generateStaticParams() {
  return [{ id: '_' }];
}

export default function Page() {
  return <TerminalDetailClient />;
}
