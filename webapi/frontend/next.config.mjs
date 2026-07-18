/** @type {import('next').NextConfig} */

// In production, emit a static export so it can be embedded into the Go
// binary via httpserver/webui. In dev (`next dev`), keep dynamic routing
// available so iteration is fast and we can hot-reload pages.
const nextConfig = {
  ...(process.env.NODE_ENV === 'production' ? { output: 'export' } : {}),

  // Dev-only: forward backend routes to the Go server on :8080 so the SPA
  // can call /api/v1/* etc. without CORS or absolute URLs.
  async rewrites() {
    return [
      { source: '/api/:path*',          destination: 'http://localhost:8080/api/:path*' },
      { source: '/login',               destination: 'http://localhost:8080/login' },
      { source: '/login/:path*',        destination: 'http://localhost:8080/login/:path*' },
      { source: '/logout',              destination: 'http://localhost:8080/logout' },
      { source: '/healthz',             destination: 'http://localhost:8080/healthz' },
      { source: '/readyz',              destination: 'http://localhost:8080/readyz' },
      { source: '/.well-known/:path*',  destination: 'http://localhost:8080/.well-known/:path*' },
      { source: '/mcp/:path*',          destination: 'http://localhost:8080/mcp/:path*' },
      { source: '/idp/:path*',          destination: 'http://localhost:8080/idp/:path*' },
      { source: '/openapi.json',        destination: 'http://localhost:8080/openapi.json' },
      { source: '/docs',                destination: 'http://localhost:8080/docs' },
    ];
  },
};

export default nextConfig;
