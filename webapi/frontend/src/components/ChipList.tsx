"use client";

// ChipList renders a string list as discrete chips rather than one joined
// run of text.
//
// The admin tables show OAuth2 scopes and grant types, which are dense and
// punctuation-heavy ("condor:/ADVERTISE_STARTD", "offline_access"). Joined
// with spaces they read as one long token and it is genuinely hard to see
// where one ends and the next begins; as chips the boundaries are visible
// without the reader parsing them.
//
// `max` caps how many render, with the remainder collapsed into a "+N" chip
// that reveals the rest on click. Clients requesting a dozen scopes would
// otherwise set the row height for the whole table.
import { useState } from "react";

export function ChipList({
  items,
  max = 6,
  tone = "gray",
  empty = "—",
}: {
  items: string[] | undefined | null;
  max?: number;
  tone?: "gray" | "blue";
  empty?: string;
}) {
  const [expanded, setExpanded] = useState(false);

  if (!items || items.length === 0) {
    return <span className="text-gray-400">{empty}</span>;
  }

  const toneClass =
    tone === "blue"
      ? "bg-blue-50 text-blue-800 ring-blue-200"
      : "bg-gray-100 text-gray-700 ring-gray-200";

  const shown = expanded ? items : items.slice(0, max);
  const hidden = items.length - shown.length;

  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((item) => (
        <span
          key={item}
          className={`inline-flex rounded-sm px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset ${toneClass}`}
        >
          {item}
        </span>
      ))}
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="inline-flex rounded-sm bg-white px-1.5 py-0.5 text-[11px] text-gray-500 ring-1 ring-inset ring-gray-200 hover:bg-gray-50 hover:text-gray-700"
          title={items.slice(max).join(" ")}
        >
          +{hidden}
        </button>
      )}
    </span>
  );
}
