// next/image's optimizer requires the Next.js server runtime, but the
// production build is a static export served by Go's webui embed.
// Using <img> tags is the right call here; suppress the lint that
// suggests next/image. The SVGs are 1–7 KB each so optimization
// wouldn't move the needle anyway.
/* eslint-disable @next/next/no-img-element */

'use client';

// Footer renders the institutional attribution band that sits below
// every page's main content.
//
// Unconfigured, that band is CHTC / Morgridge / UW-Madison: the CHTC
// logo is the link target -- clicking anywhere on it opens the CHTC
// homepage in a new tab -- and the Morgridge and UW-Madison crests are
// static attribution (the institutions hosting and supporting the
// Center for High Throughput Computing). They don't link out, partly to
// avoid implying affiliation with the broader university websites and
// partly because the user goal of the footer is "where do I learn about
// CHTC?".
//
// A site that runs its own access point configures its own band
// (HTTP_API_WEBUI_FOOTER_LOGOS), because the shipped one answers the
// question "who runs this service?" with the wrong institution. When it
// does, the band is followed by one small line naming HTCondor and
// CHTC: who runs the service and who wrote the software are different
// questions, and replacing the answer to the first should not erase the
// second.
//
// Plain <img> tags rather than next/image: the production build is
// a static export served by the Go binary's embed, and next/image's
// optimizer relies on the Next.js server runtime that doesn't run
// in that mode. Using <img> sidesteps the dance and the SVGs are
// already small (~1-7 KB).
//
// Logo source files live in /public/logos/ and were cribbed from
// reference/swamp/, with each institution's official artwork. A site's
// own images are served from HTTP_API_WEBUI_BRANDING_DIR under
// /branding/.

import { useBranding } from '@/lib/branding';

const CHTC_HOMEPAGE = 'https://chtc.cs.wisc.edu/';
const HTCONDOR_HOMEPAGE = 'https://htcondor.org/';

export function Footer() {
  const branding = useBranding();
  const logos = branding.footer_logos;

  return (
    <footer className="border-t border-gray-200 bg-white">
      <div className="mx-auto max-w-6xl px-4 py-6 lg:px-8">
        {logos ? (
          logos.length > 0 && (
            <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-4">
              {logos.map((logo) => {
                const img = (
                  <img src={logo.src} alt={logo.alt} title={logo.alt} className="h-10 w-auto" />
                );
                return logo.href ? (
                  <a
                    key={logo.src}
                    href={logo.href}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center transition-opacity hover:opacity-75"
                    title={logo.alt}
                  >
                    {img}
                  </a>
                ) : (
                  <span key={logo.src} className="inline-flex items-center">
                    {img}
                  </span>
                );
              })}
            </div>
          )
        ) : (
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
        )}

        {branding.software_credit && (
          <p
            className={`text-center text-xs text-gray-500 ${logos && logos.length > 0 ? 'mt-4' : ''}`}
          >
            Powered by{' '}
            <a
              href={HTCONDOR_HOMEPAGE}
              target="_blank"
              rel="noreferrer noopener"
              className="underline hover:text-gray-700"
            >
              HTCondor
            </a>
            , from the{' '}
            <a
              href={CHTC_HOMEPAGE}
              target="_blank"
              rel="noreferrer noopener"
              className="underline hover:text-gray-700"
            >
              Center for High Throughput Computing
            </a>
            .
          </p>
        )}
      </div>
    </footer>
  );
}
