// Whether this access point lets anything reach into a running job.
//
// A site can forbid condor_ssh_to_job outright, and then the terminal
// on a job page cannot connect however long it tries. The server says
// so in the session (`ssh_to_job`), the same way it says which
// interactive applications it offers, so the page can leave the
// terminal out rather than offer one that fails at the connect -- which
// reads as a bug in the page rather than as a decision somebody made.
//
// Reading a job is unaffected: output, files and the live tail come
// from the spool and the starter, not from a shell in the sandbox.

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useSSHToJob(): boolean {
  const { data } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  // Undefined while the session loads, and from a server too old to
  // say. Both read as allowed, which is what the page did before the
  // field existed: offering a terminal that then refuses is a smaller
  // failure than hiding one that works.
  return data?.ssh_to_job !== false;
}
