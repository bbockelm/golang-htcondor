import ArchiveDetailClient from './ArchiveDetailClient';

// Required for Next.js static export. Mirrors /jobs/[id]/page.tsx —
// we emit a single placeholder (`_`) and let the Go-side SPA handler
// resolve any /archive/<id> URL to this generated page; the client
// reads the real ID from the URL via useResolvedParams.
export function generateStaticParams() {
  return [{ id: '_' }];
}

export default function Page() {
  return <ArchiveDetailClient />;
}
