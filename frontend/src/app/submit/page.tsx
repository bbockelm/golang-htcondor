'use client';

// Batch submission page, split into three explicit sections:
//
//   1. Template — defines the body of the submit file (everything but
//      the trailing `queue` line). Two modes: pick from the library, or
//      write your own. "Save as template" persists a written template.
//
//   2. Table — one row per job in the batch, columns named by the
//      template's variables. The page synthesizes
//      `queue <cols> from ((...))` from this.
//
//   3. Inputs — file uploads attached after submission.

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  api,
  ApiError,
  type Template,
} from '@/lib/api';
import { Dropzone, type DroppedFile } from '@/components/Dropzone';

type TemplateMode = 'library' | 'custom';

interface CustomDraft {
  name: string;
  description: string;
  columnsCSV: string;
  contents: string;
}

const STARTER_DRAFT: CustomDraft = {
  name: '',
  description: '',
  columnsCSV: 'name',
  contents: `# Submit-file body. Reference table columns as $(name).
# Do NOT include a queue line — the table section adds it for you.

executable = /bin/bash
transfer_executable = false
arguments  = "-c 'echo Hello, $(name)!'"
output     = hello-$(ProcId).out
error      = hello-$(ProcId).err
log        = hello.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
`,
};

export default function SubmitPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // --- Template section state ---------------------------------------
  const [mode, setMode] = useState<TemplateMode>('library');
  const [selectedID, setSelectedID] = useState<string>('');
  const [draft, setDraft] = useState<CustomDraft>(STARTER_DRAFT);

  const tplQuery = useQuery({
    queryKey: ['templates'],
    queryFn: api.templates.list,
  });
  const templates = tplQuery.data?.templates ?? [];

  // Auto-select the first library template once the list loads.
  useEffect(() => {
    if (mode !== 'library' || selectedID || templates.length === 0) return;
    setSelectedID(templates[0].id);
  }, [mode, selectedID, templates]);

  const selected = templates.find((t) => t.id === selectedID);

  // The currently-active template — either picked from library or
  // synthesized from the custom draft.
  const active = useMemo<{
    name: string;
    columns: string[];
    contents: string;
  }>(() => {
    if (mode === 'library' && selected) {
      return {
        name: selected.name,
        columns: selected.columns,
        contents: selected.contents,
      };
    }
    return {
      name: draft.name || '(new template)',
      columns: parseColumnsCSV(draft.columnsCSV),
      contents: draft.contents,
    };
  }, [mode, selected, draft]);

  // --- Table section state ------------------------------------------
  const [rows, setRows] = useState<string[][]>([['']]);

  // Re-shape rows whenever the active template's columns change.
  useEffect(() => {
    setRows((prev) => reshapeRows(prev, active.columns));
  }, [active.columns]);

  // --- Inputs section state -----------------------------------------
  const [files, setFiles] = useState<DroppedFile[]>([]);

  // --- Submit -------------------------------------------------------
  const submit = useMutation({
    mutationFn: async () => {
      const body = buildSubmitFile(active.contents, active.columns, rows);
      const submitted = await api.jobs.submit(body);
      if (submitted.job_ids.length > 0 && files.length > 0) {
        await api.jobs.uploadInputs(
          submitted.job_ids[0],
          files.map((f) => ({
            name: f.name,
            file: f.file,
            executable: f.executable,
          })),
        );
      }
      return submitted;
    },
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      router.push(`/jobs/${res.job_ids[0]}`);
    },
  });

  // --- Save-as-template ---------------------------------------------
  const saveTpl = useMutation({
    mutationFn: () =>
      api.templates.save({
        name: draft.name,
        description: draft.description,
        columns: parseColumnsCSV(draft.columnsCSV),
        contents: draft.contents,
      }),
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
      // Switch to library mode and select the new entry.
      setMode('library');
      setSelectedID(saved.id);
    },
  });

  const submitDisabled =
    submit.isPending ||
    !active.contents.trim() ||
    rows.length === 0 ||
    rows.some((r) => r.every((c) => c.trim() === ''));

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Submit a Batch</h1>
        <p className="text-sm text-gray-500">
          Pick or write a template, fill the table with one row per job,
          attach any input files, then submit.
        </p>
      </div>

      <TemplateSection
        mode={mode}
        setMode={setMode}
        templates={templates}
        loading={tplQuery.isLoading}
        loadError={tplQuery.error as Error | null}
        selectedID={selectedID}
        setSelectedID={setSelectedID}
        draft={draft}
        setDraft={setDraft}
        onSave={() => saveTpl.mutate()}
        saveState={saveTpl}
      />

      <TableSection
        columns={active.columns}
        rows={rows}
        setRows={setRows}
      />

      <InputsSection files={files} setFiles={setFiles} disabled={submit.isPending} />

      {submit.isError && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {submit.error instanceof ApiError
            ? `${submit.error.status}: ${submit.error.message}`
            : (submit.error as Error).message}
        </div>
      )}

      <div className="flex items-center gap-3">
        <button
          onClick={() => submit.mutate()}
          disabled={submitDisabled}
          className="rounded bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          {submit.isPending ? 'Submitting…' : `Submit batch (${rows.length} job${rows.length === 1 ? '' : 's'})`}
        </button>
        <span className="text-xs text-gray-500">
          Submitting as <code>{active.name}</code>.
        </span>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// Template section: visual card with a Library/Custom toggle.
// ----------------------------------------------------------------------

function TemplateSection({
  mode,
  setMode,
  templates,
  loading,
  loadError,
  selectedID,
  setSelectedID,
  draft,
  setDraft,
  onSave,
  saveState,
}: {
  mode: TemplateMode;
  setMode: (m: TemplateMode) => void;
  templates: Template[];
  loading: boolean;
  loadError: Error | null;
  selectedID: string;
  setSelectedID: (id: string) => void;
  draft: CustomDraft;
  setDraft: (d: CustomDraft) => void;
  onSave: () => void;
  saveState: { isPending: boolean; error: unknown };
}) {
  const selected = templates.find((t) => t.id === selectedID);

  return (
    <SectionCard
      title="1. Template"
      subtitle="Define the submit-file body and which columns the table will fill in."
    >
      <div className="inline-flex rounded-md border border-gray-300 bg-white p-0.5 text-sm">
        <ModeButton active={mode === 'library'} onClick={() => setMode('library')}>
          Use template from library
        </ModeButton>
        <ModeButton active={mode === 'custom'} onClick={() => setMode('custom')}>
          Write new template
        </ModeButton>
      </div>

      {mode === 'library' ? (
        <div className="space-y-3 mt-3">
          {loading && <p className="text-sm text-gray-400">Loading templates…</p>}
          {loadError && (
            <p className="text-sm text-red-600">
              Could not load templates: {loadError.message}
            </p>
          )}
          {!loading && templates.length === 0 && (
            <p className="text-sm text-gray-500">No templates available.</p>
          )}
          {templates.length > 0 && (
            <>
              <label className="block">
                <span className="text-sm font-medium text-gray-700">Template</span>
                <select
                  value={selectedID}
                  onChange={(e) => setSelectedID(e.target.value)}
                  className="mt-1 w-full rounded border border-gray-300 bg-white px-3 py-1.5 text-sm"
                >
                  {groupBySource(templates).map((group) => (
                    <optgroup key={group.label} label={group.label}>
                      {group.items.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.name}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </label>
              {selected && (
                <div className="rounded border border-gray-200 bg-gray-50 p-3 text-xs space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-700">{selected.name}</span>
                    <SourceBadge source={selected.source} />
                  </div>
                  {selected.description && (
                    <p className="text-gray-600">{selected.description}</p>
                  )}
                  <div className="text-gray-600">
                    Columns:{' '}
                    {selected.columns.length === 0 ? (
                      <em>none (single fixed job)</em>
                    ) : (
                      selected.columns.map((c) => (
                        <code
                          key={c}
                          className="ml-1 rounded bg-white border border-gray-200 px-1 py-0.5"
                        >
                          {c}
                        </code>
                      ))
                    )}
                  </div>
                  <details className="pt-1">
                    <summary className="cursor-pointer text-gray-500 hover:text-gray-700">
                      Show submit-file body
                    </summary>
                    <pre className="mt-2 max-h-64 overflow-auto rounded border border-gray-200 bg-white p-2 font-mono text-[11px]">
                      {selected.contents}
                    </pre>
                  </details>
                </div>
              )}
            </>
          )}
        </div>
      ) : (
        <CustomDraftEditor
          draft={draft}
          setDraft={setDraft}
          onSave={onSave}
          saveState={saveState}
        />
      )}
    </SectionCard>
  );
}

function CustomDraftEditor({
  draft,
  setDraft,
  onSave,
  saveState,
}: {
  draft: CustomDraft;
  setDraft: (d: CustomDraft) => void;
  onSave: () => void;
  saveState: { isPending: boolean; error: unknown };
}) {
  const canSave = draft.name.trim() !== '' && draft.contents.trim() !== '';
  return (
    <div className="space-y-3 mt-3">
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name">
          <input
            type="text"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder="My Pipeline"
            className="w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
          />
        </Field>
        <Field label="Columns (comma-separated)">
          <input
            type="text"
            value={draft.columnsCSV}
            onChange={(e) => setDraft({ ...draft, columnsCSV: e.target.value })}
            placeholder="name, seconds"
            className="w-full rounded border border-gray-300 px-3 py-1.5 font-mono text-sm"
          />
        </Field>
      </div>
      <Field label="Description (optional)">
        <input
          type="text"
          value={draft.description}
          onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          placeholder="One-line description"
          className="w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
        />
      </Field>
      <Field label="Submit-file body">
        <textarea
          value={draft.contents}
          onChange={(e) => setDraft({ ...draft, contents: e.target.value })}
          spellCheck={false}
          className="w-full h-64 rounded border border-gray-300 px-3 py-2 font-mono text-xs"
        />
        <p className="mt-1 text-xs text-gray-500">
          Reference table columns as <code>$(columnName)</code>. Don&apos;t add
          a <code>queue</code> line — the table section synthesizes one.
        </p>
      </Field>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onSave}
          disabled={!canSave || saveState.isPending}
          className="rounded border border-gray-300 bg-white px-3 py-1.5 text-sm hover:bg-gray-50 disabled:opacity-50"
          title="Persist this template to the library"
        >
          {saveState.isPending ? 'Saving…' : 'Save as template'}
        </button>
        {saveState.error ? (
          <span className="text-xs text-red-600">
            Save failed:{' '}
            {saveState.error instanceof ApiError
              ? saveState.error.message
              : String(saveState.error)}
          </span>
        ) : null}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// Table section: one row per job. Column headers come from the active
// template; the user fills cells.
// ----------------------------------------------------------------------

function TableSection({
  columns,
  rows,
  setRows,
}: {
  columns: string[];
  rows: string[][];
  setRows: (r: string[][]) => void;
}) {
  return (
    <SectionCard
      title="2. Table"
      subtitle={
        columns.length === 0
          ? 'This template has no variable columns; one row = one job.'
          : `Column headers come from the template. ${rows.length} row${rows.length === 1 ? '' : 's'} = ${rows.length} job${rows.length === 1 ? '' : 's'}.`
      }
    >
      {columns.length === 0 ? (
        <div className="text-sm text-gray-500">
          Single fixed job. Click <em>Submit batch</em> to send 1 job.
        </div>
      ) : (
        <div className="space-y-2">
          <CSVImporter columns={columns} setRows={setRows} />
          <div className="overflow-x-auto rounded border border-gray-200 bg-white">
            <table className="min-w-full text-sm border-collapse">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-2 py-1 w-10 text-right text-gray-400 border-b border-gray-200">
                    #
                  </th>
                  {columns.map((c) => (
                    <th
                      key={c}
                      className="px-2 py-1 font-mono border-b border-l border-gray-200"
                    >
                      {c}
                    </th>
                  ))}
                  <th className="px-2 py-1 w-1 border-b border-l border-gray-200" />
                </tr>
              </thead>
              <tbody>
                {rows.map((row, ri) => (
                  <tr key={ri} className="border-b border-gray-100">
                    <td className="px-2 py-1 text-right text-xs text-gray-400">
                      {ri + 1}
                    </td>
                    {columns.map((_, ci) => (
                      <td key={ci} className="px-1 py-0.5 border-l border-gray-200">
                        {/*
                          Always render a visible 1-px border on every
                          cell input. The previous "border-transparent
                          + hover-only" design made it look like the
                          cells were inert text; users couldn't tell
                          they were supposed to fill them in.
                        */}
                        <input
                          type="text"
                          value={row[ci] ?? ''}
                          onChange={(e) => {
                            const next = rows.map((r) => [...r]);
                            next[ri][ci] = e.target.value;
                            setRows(next);
                          }}
                          className="w-full rounded border border-gray-300 bg-white px-2 py-0.5 font-mono text-xs hover:border-gray-400 focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1 text-right border-l border-gray-200">
                      <button
                        type="button"
                        onClick={() => setRows(rows.filter((_, i) => i !== ri))}
                        className="text-xs text-gray-400 hover:text-red-600"
                        title="Remove row"
                        disabled={rows.length === 1}
                      >
                        ×
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setRows([...rows, columns.map(() => '')])}
              className="rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-50"
            >
              + Add row
            </button>
            <button
              type="button"
              onClick={() =>
                setRows([...rows, ...rows.map((r) => [...r])])
              }
              className="rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-50"
              title="Duplicate every row (handy for parameter sweeps)"
            >
              × Duplicate all
            </button>
          </div>
        </div>
      )}
    </SectionCard>
  );
}

// ----------------------------------------------------------------------
// CSV importer: paste-area + file picker. Replaces the table contents
// when the user applies a CSV. We accept the file in either of two
// shapes: header row matching template columns (consumed and dropped)
// or no header at all (every row is data).
// ----------------------------------------------------------------------

function CSVImporter({
  columns,
  setRows,
}: {
  columns: string[];
  setRows: (r: string[][]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [paste, setPaste] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const apply = (text: string, source: 'paste' | 'file', filename?: string) => {
    setError(null);
    setInfo(null);
    let parsed: string[][];
    try {
      parsed = parseCSV(text);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    // Drop empty rows.
    parsed = parsed.filter((r) => !(r.length === 1 && r[0].trim() === ''));
    if (parsed.length === 0) {
      setError('CSV is empty.');
      return;
    }

    let droppedHeader = false;
    if (rowMatchesHeader(parsed[0], columns)) {
      parsed = parsed.slice(1);
      droppedHeader = true;
    }

    if (parsed.length === 0) {
      setError('CSV had a header but no data rows.');
      return;
    }

    // Validate column counts. We tolerate too-few cells (pad with
    // empty strings) but refuse too-many cells — that's almost
    // always a column-mismatch typo.
    for (let i = 0; i < parsed.length; i++) {
      if (parsed[i].length > columns.length) {
        setError(
          `Row ${i + 1} has ${parsed[i].length} values but the template has ${columns.length} columns. (Did you pick the wrong template?)`,
        );
        return;
      }
      while (parsed[i].length < columns.length) parsed[i].push('');
    }

    setRows(parsed);
    const noun = parsed.length === 1 ? 'row' : 'rows';
    const where = source === 'file' ? ` from ${filename ?? 'file'}` : '';
    const headerNote = droppedHeader ? ' (dropped header row)' : '';
    setInfo(`Imported ${parsed.length} ${noun}${where}${headerNote}.`);
    setPaste('');
    setOpen(false);
  };

  const onFile = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onerror = () => setError(`Could not read ${file.name}`);
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      apply(text, 'file', file.name);
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-gray-500">Or import:</span>
        <button
          type="button"
          onClick={() => {
            setOpen((o) => !o);
            setError(null);
            setInfo(null);
          }}
          className="rounded border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50"
        >
          {open ? 'Cancel paste' : 'Paste CSV'}
        </button>
        <label className="rounded border border-gray-300 bg-white px-2 py-0.5 text-gray-700 hover:bg-gray-50 cursor-pointer">
          Upload CSV
          <input
            type="file"
            accept=".csv,text/csv"
            className="sr-only"
            onChange={(e) => {
              onFile(e.target.files?.[0]);
              // Reset so re-selecting the same file fires onChange.
              e.target.value = '';
            }}
          />
        </label>
        {info && <span className="text-green-700">{info}</span>}
        {error && <span className="text-red-700">{error}</span>}
      </div>
      {open && (
        <div className="space-y-1">
          <textarea
            value={paste}
            onChange={(e) => setPaste(e.target.value)}
            spellCheck={false}
            placeholder={
              `# Paste CSV here. First row may be a header matching the\n` +
              `# template columns (${columns.join(', ')}); otherwise every row is data.\n` +
              columns.join(',') +
              '\n'
            }
            className="w-full h-32 rounded border border-gray-300 bg-white px-2 py-1 font-mono text-xs"
          />
          <div className="flex gap-2">
            <button
              type="button"
              disabled={paste.trim() === ''}
              onClick={() => apply(paste, 'paste')}
              className="rounded bg-brand-600 px-2 py-1 text-xs text-white hover:bg-brand-700 disabled:opacity-50"
            >
              Replace table with this CSV
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// rowMatchesHeader returns true if `row` looks like a header row for
// the template's column list — exact match, case-insensitive on the
// labels (HTCondor macro names are case-sensitive but humans editing
// CSVs in spreadsheet apps frequently aren't). We compare only when
// lengths match; mismatched lengths are handled later as data-row
// validation.
function rowMatchesHeader(row: string[], columns: string[]): boolean {
  if (row.length !== columns.length) return false;
  for (let i = 0; i < columns.length; i++) {
    if (row[i].trim().toLowerCase() !== columns[i].toLowerCase()) return false;
  }
  return true;
}

// parseCSV is a small RFC 4180-flavored parser:
//   - comma separators
//   - double-quoted fields preserve commas / newlines
//   - embedded "" inside a quoted field decodes as one "
//   - trailing CR before LF is stripped
// Throws on unterminated quoted fields with a useful row index so the
// importer can surface a helpful error. Avoids pulling in a CSV
// library for what amounts to ~40 lines.
function parseCSV(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;
  let lineNo = 1;

  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (inQuotes) {
      if (c === '"') {
        if (input[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cell += c;
        if (c === '\n') lineNo++;
      }
      continue;
    }
    if (c === '"' && cell === '') {
      inQuotes = true;
      continue;
    }
    if (c === ',') {
      row.push(cell);
      cell = '';
      continue;
    }
    if (c === '\n' || c === '\r') {
      row.push(cell);
      cell = '';
      rows.push(row);
      row = [];
      // Eat \r\n as a single newline.
      if (c === '\r' && input[i + 1] === '\n') i++;
      lineNo++;
      continue;
    }
    cell += c;
  }
  if (inQuotes) {
    throw new Error(`Unterminated quoted field at line ${lineNo}`);
  }
  // Final cell / row if not newline-terminated.
  if (cell !== '' || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

// ----------------------------------------------------------------------
// Inputs section: file uploads.
// ----------------------------------------------------------------------

function InputsSection({
  files,
  setFiles,
  disabled,
}: {
  files: DroppedFile[];
  setFiles: (f: DroppedFile[]) => void;
  disabled: boolean;
}) {
  return (
    <SectionCard
      title="3. Inputs"
      subtitle="Files dropped here are uploaded after submission and put in the job sandbox."
    >
      <Dropzone files={files} onChange={setFiles} disabled={disabled} />
    </SectionCard>
  );
}

// ----------------------------------------------------------------------
// Shared visual primitives.
// ----------------------------------------------------------------------

function SectionCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-gray-200 bg-white shadow-sm">
      <header className="border-b border-gray-200 bg-gray-50 px-4 py-2.5 rounded-t-lg">
        <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
        {subtitle && <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function ModeButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded px-3 py-1 text-sm transition-colors ${
        active
          ? 'bg-brand-600 text-white'
          : 'bg-transparent text-gray-700 hover:bg-gray-100'
      }`}
    >
      {children}
    </button>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-gray-700">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

function SourceBadge({ source }: { source: Template['source'] }) {
  const label =
    source === 'builtin' ? 'built-in' : source === 'global' ? 'global' : 'mine';
  const cls =
    source === 'user'
      ? 'bg-blue-100 text-blue-800'
      : 'bg-gray-200 text-gray-700';
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wide font-medium ${cls}`}
    >
      {label}
    </span>
  );
}

// ----------------------------------------------------------------------
// Pure helpers.
// ----------------------------------------------------------------------

function parseColumnsCSV(s: string): string[] {
  return s
    .split(',')
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
}

function reshapeRows(prev: string[][], cols: string[]): string[][] {
  if (cols.length === 0) {
    return prev.length === 0 ? [[]] : prev.map(() => []);
  }
  if (prev.length === 0) {
    return [cols.map(() => '')];
  }
  return prev.map((r) => {
    const next = cols.map((_, i) => r[i] ?? '');
    return next;
  });
}

// buildSubmitFile glues a template's body to a synthesized
// `queue cols from ((...))` line. We emit the table inline rather than
// shipping a CSV file to keep submission a single API call.
//
// HTCondor's "queue ... from ((...))" syntax accepts whitespace-
// separated row records inside double parens. We quote each cell so
// values containing spaces survive intact.
function buildSubmitFile(
  contents: string,
  columns: string[],
  rows: string[][],
): string {
  const body = contents.trimEnd();
  if (columns.length === 0) {
    return `${body}\nqueue\n`;
  }
  const colsLine = columns.join(', ');
  const rowsBody = rows
    .filter((r) => !r.every((c) => c.trim() === ''))
    .map((r) => r.map(quoteCell).join(' '))
    .join('\n  ');
  return `${body}\nqueue ${colsLine} from ((\n  ${rowsBody}\n))\n`;
}

function quoteCell(s: string): string {
  // HTCondor's macro expansion handles quoted strings well; quote
  // anything with whitespace or a quote char to keep the row record
  // unambiguous.
  if (/[\s"']/.test(s)) {
    return '"' + s.replace(/"/g, '\\"') + '"';
  }
  return s;
}

function groupBySource(
  list: Template[],
): { label: string; items: Template[] }[] {
  const groups: Record<Template['source'], Template[]> = {
    user: [],
    global: [],
    builtin: [],
  };
  for (const t of list) groups[t.source].push(t);
  const out: { label: string; items: Template[] }[] = [];
  if (groups.user.length) out.push({ label: 'My templates', items: groups.user });
  if (groups.global.length) out.push({ label: 'Site templates', items: groups.global });
  if (groups.builtin.length) out.push({ label: 'Built-in', items: groups.builtin });
  return out;
}
