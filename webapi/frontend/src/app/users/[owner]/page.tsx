import UserDetailClient from './UserDetailClient';

// Static-export placeholder: the Go SPA handler (resolveDynamicRoute)
// resolves any /users/<owner> URL to this generated `_` page, and the
// client reads the real owner from the URL via useResolvedParams.
export function generateStaticParams() {
  return [{ owner: '_' }];
}

export default function Page() {
  return <UserDetailClient />;
}
