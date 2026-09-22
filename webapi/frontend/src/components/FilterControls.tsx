'use client';

// The two-mode filter shared by the listing pages: a free-text substring
// match applied in the browser, or a raw ClassAd expression sent to the
// server as a query constraint.
//
// Text is the default on every page that uses it. An expression is the
// precise tool and the one worth reaching for on a big pool, but it is
// also the one that returns nothing at all when you get it slightly wrong,
// so it is not what a page opens with.
//
// The expression form applies on submit rather than on each keystroke:
// every intermediate state of a half-typed expression is either a syntax
// error or a different query, and sending those to the server as the user
// types would flash errors and burn queries.

export type FilterMode = 'text' | 'expr';

export function FilterControls({
  mode,
  input,
  onMode,
  onInput,
  onApplyExpr,
  textPlaceholder,
  exprPlaceholder,
}: {
  mode: FilterMode;
  input: string;
  onMode: (m: FilterMode) => void;
  onInput: (v: string) => void;
  onApplyExpr: () => void;
  textPlaceholder: string;
  exprPlaceholder: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="inline-flex overflow-hidden rounded-sm border border-gray-300">
        {(['text', 'expr'] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => onMode(m)}
            aria-pressed={mode === m}
            className={`px-3 py-1.5 text-sm ${
              mode === m
                ? 'bg-brand-600 text-white'
                : 'bg-white text-gray-600 hover:bg-gray-50'
            }`}
          >
            {m === 'text' ? 'Text' : 'ClassAd expression'}
          </button>
        ))}
      </div>
      {mode === 'text' ? (
        <input
          type="text"
          value={input}
          onChange={(e) => onInput(e.target.value)}
          placeholder={textPlaceholder}
          className="min-w-[20rem] flex-1 rounded-sm border border-gray-300 px-3 py-1.5 text-sm"
        />
      ) : (
        <form
          className="flex flex-1 items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            onApplyExpr();
          }}
        >
          <input
            type="text"
            value={input}
            onChange={(e) => onInput(e.target.value)}
            placeholder={exprPlaceholder}
            spellCheck={false}
            className="min-w-[20rem] flex-1 rounded-sm border border-gray-300 px-3 py-1.5 font-mono text-sm"
          />
          <button
            type="submit"
            className="rounded-sm bg-brand-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
          >
            Apply
          </button>
        </form>
      )}
    </div>
  );
}
