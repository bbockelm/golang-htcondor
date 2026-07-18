// next/image's optimizer requires the Next.js server runtime, but the
// production build is a static export served by Go's webui embed.
// Using <img> tags is the right call here; suppress the lint that
// suggests next/image. The SVGs are 1–7 KB each so optimization
// wouldn't move the needle anyway.
/* eslint-disable @next/next/no-img-element */

// Footer renders the CHTC / Morgridge / UW-Madison institutional
// attribution band that sits below every page's main content. The
// CHTC logo is the link target — clicking anywhere on it opens the
// CHTC homepage in a new tab. The Morgridge and UW-Madison crests
// are presented as static attribution (the institutions hosting and
// supporting the Center for High Throughput Computing); they don't
// link out, partly to avoid implying affiliation with the broader
// university websites and partly because the user goal of the
// footer is "where do I learn about CHTC?".
//
// Plain <img> tags rather than next/image: the production build is
// a static export served by the Go binary's embed, and next/image's
// optimizer relies on the Next.js server runtime that doesn't run
// in that mode. Using <img> sidesteps the dance and the SVGs are
// already small (~1-7 KB).
//
// Logo source files live in /public/logos/ and were cribbed from
// reference/swamp/, with each institution's official artwork.

const CHTC_HOMEPAGE = 'https://chtc.cs.wisc.edu/';

export function Footer() {
  return (
    <footer className="border-t border-gray-200 bg-white">
      <div className="mx-auto max-w-6xl px-4 py-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-4">
          <a
            href={CHTC_HOMEPAGE}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center transition-opacity hover:opacity-75"
            title="Center for High Throughput Computing"
          >
            <img
              src="/logos/CHTC_Logo_Full_Color.svg"
              alt="Center for High Throughput Computing"
              className="h-10 w-auto"
            />
          </a>
          <img
            src="/logos/Morgridge_Logo.svg"
            alt="Morgridge Institute for Research"
            className="h-10 w-auto"
            title="Morgridge Institute for Research"
          />
          <img
            src="/logos/UW_Crest.svg"
            alt="University of Wisconsin–Madison"
            className="h-12 w-auto"
            title="University of Wisconsin–Madison"
          />
        </div>
      </div>
    </footer>
  );
}
