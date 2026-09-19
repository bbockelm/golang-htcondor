import SlotDetailClient from './SlotDetailClient';

// Static-export placeholder: the Go SPA handler (resolveDynamicRoute)
// resolves any /pool/slots/<name> URL to this generated `_` page, and the
// client reads the real slot name from the URL via useResolvedParams.
export function generateStaticParams() {
  return [{ name: '_' }];
}

export default function Page() {
  return <SlotDetailClient />;
}
