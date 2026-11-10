import BatchDetailClient from './BatchDetailClient';

// Required for Next.js static export: one placeholder page (`_`) that the
// Go-side SPA handler serves for any /batches/<id>; the client reads the
// real id from the URL via useResolvedParams.
export function generateStaticParams() {
  return [{ id: '_' }];
}

export default function Page() {
  return <BatchDetailClient />;
}
