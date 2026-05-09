'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export default function InfoPage() {
  const { data: session, isLoading: sessionLoading, error: sessionError } =
    useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  const { data: version, isLoading: versionLoading, error: versionError } =
    useQuery({ queryKey: ['version'], queryFn: api.version });

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Info</h1>
        <p className="text-sm text-gray-500">
          Build information for this access point and details about your
          current session.
        </p>
      </div>

      <Section title="Web app">
        {versionLoading && <p className="text-gray-400 text-sm">Loading...</p>}
        {versionError && (
          <p className="text-red-600 text-sm">
            Could not load version: {(versionError as Error).message}
          </p>
        )}
        {version && (
          <DefList>
            <Row label="Version" value={version.version || '(unset)'} />
            <Row label="Commit" mono value={version.commit || '(unset)'} />
          </DefList>
        )}
      </Section>

      <Section title="Signed-in user">
        {sessionLoading && <p className="text-gray-400 text-sm">Loading...</p>}
        {sessionError && (
          <p className="text-red-600 text-sm">
            Could not load session: {(sessionError as Error).message}
          </p>
        )}
        {session && !session.authenticated && (
          <p className="text-sm text-gray-500">
            Not signed in.{' '}
            <a
              href="/login"
              className="text-brand-700 hover:text-brand-900 underline"
            >
              Sign in
            </a>
            .
          </p>
        )}
        {session?.authenticated && (
          <DefList>
            <Row label="Username" value={session.username ?? '(unknown)'} />
            <Row
              label="Admin"
              value={session.is_admin ? 'Yes' : 'No'}
            />
            <Row
              label="Groups"
              value={
                session.groups && session.groups.length > 0 ? (
                  <ul className="space-y-0.5">
                    {session.groups.map((g) => (
                      <li key={g} className="font-mono text-xs">
                        {g}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-gray-500">none</span>
                )
              }
            />
          </DefList>
        )}
      </Section>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-gray-900 mb-3">{title}</h2>
      {children}
    </section>
  );
}

function DefList({ children }: { children: React.ReactNode }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
      {children}
    </dl>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-gray-500">{label}</dt>
      <dd
        className={`text-gray-900 break-all ${mono ? 'font-mono text-xs' : ''}`}
      >
        {value}
      </dd>
    </>
  );
}
