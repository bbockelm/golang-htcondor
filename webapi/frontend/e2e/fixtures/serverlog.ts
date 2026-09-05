import { readFileSync } from 'node:fs';

// serverLog returns the harness's captured server output, which the
// credential fixtures scrape the generated passwords out of.
//
// E2E_SERVER_LOG is required rather than defaulting to a fixed path.
// A shared /tmp filename is both a collision (two runs on one host
// clobber each other, and the second reads the first's credentials)
// and, on a multi-user host, somewhere another user can plant a symlink
// or squat the name. The harness picks a private directory per run and
// passes it in.
export function serverLog(): string {
  const path = process.env.E2E_SERVER_LOG;
  if (!path) {
    throw new Error(
      'E2E_SERVER_LOG is not set. The full suite needs the harness\'s server ' +
        'output to read the generated credentials; scripts/e2e-server.sh ' +
        'prints the path it wrote them to.',
    );
  }
  return readFileSync(path, 'utf8');
}
