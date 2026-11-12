// Which built-in interactive applications this access point offers.
//
// The server says so in the session (`interactive`), because the three
// are configuration and not something the browser can work out: an app
// that is not offered refuses a launch, and a page that offered the
// form anyway would be asking the user to fill one in to be told no.
//
// Undefined until the session has loaded, and for a server too old to
// say. Both are treated as "offered", which is what this page did
// before the setting existed -- a launch that is in fact refused says
// so, while hiding a working app shows nothing at all.

import { useQuery } from '@tanstack/react-query';
import { api, type InteractiveApp } from '@/lib/api';

export function useInteractiveApps(): InteractiveApp[] | undefined {
  const { data } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  // Undefined for both "still loading" and "the server did not say".
  // Deliberately NOT coerced to []: an access point that offers none
  // sends an empty list, and a server too old to know about the field
  // sends nothing at all. Coercing the second into the first hid all
  // three applications from everybody talking to an older server.
  return data?.interactive;
}

// useInteractiveAppOffered is false only when the session has loaded and
// says this app is not offered. Callers compare against false rather
// than falling back on truthiness, so a session still loading does not
// flash the app away and back.
export function useInteractiveAppOffered(app: InteractiveApp): boolean | undefined {
  const offered = useInteractiveApps();
  return offered === undefined ? undefined : offered.includes(app);
}
