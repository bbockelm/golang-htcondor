import JobDetailClient from './JobDetailClient';

// Required for Next.js static export. We emit a single placeholder
// (`_`) and let the Go-side SPA handler resolve any /jobs/<id> URL to
// this generated page; the client reads the real ID from the URL via
// useResolvedParams. See httpserver/webui/handler.go (resolveDynamicRoute).
export function generateStaticParams() {
  return [{ id: '_' }];
}

export default function Page() {
  return <JobDetailClient />;
}
