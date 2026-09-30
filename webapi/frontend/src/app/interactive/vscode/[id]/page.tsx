import VSCodeDetailClient from './VSCodeDetailClient';

// Required for Next.js static export. We emit a single placeholder; the
// Go-side handler resolves any /interactive/vscode/<id> URL to this
// page (webui/handler.go falls back to a "_" segment), and the client
// picks up the real id via useResolvedParams.
export function generateStaticParams() {
  return [{ id: '_' }];
}

export default function Page() {
  return <VSCodeDetailClient />;
}
