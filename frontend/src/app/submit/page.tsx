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
  MAX_TEMPLATE_INPUT_FILE_BYTES,
  type Template,
  type TemplateColumn,
  type TemplateInputFile,
} from '@/lib/api';
import { Dropzone, type DroppedFile } from '@/components/Dropzone';
import {
  ResourceRequestPanel,
  DEFAULT_RESOURCE_REQUEST,
  type ResourceRequest,
} from '@/components/ResourceRequest';
import {
  applyResourcesToBody,
  bodyHasCoreResourceRequests,
  bodyHasResourceRequests,
  ensureTransferInput,
  getAttribute,
  readResourcesFromBody,
  setAttribute,
} from '@/lib/submitFile';

type TemplateMode = 'library' | 'custom';

interface CustomDraft {
  name: string;
  description: string;
  columns: TemplateColumn[];
  contents: string;
  // Default attachments saved with the template. The shape mirrors
  // TemplateInputFile but we keep size around for the UI ("3 KB,
  // shell-script") since base64-decoding to learn the size every
  // render is wasteful.
  inputFiles: DraftInputFile[];
  // Optional inline executable script — the "I want to write a quick
  // shell script right here, no separate file" affordance. Belongs to
  // the template editor (custom mode only) since the script is part
  // of the template. When non-null, an effect at the SubmitPage level
  // keeps the submit-file body's `executable` and
  // `transfer_executable` lines in sync with the script's name.
  inlineScript: InlineScript | null;
}

// InlineScript carries the editor's state. Persisted as one of the
// template's input_files on save (and as a per-batch attachment on
// submit) so the downstream pipeline doesn't need to special-case it.
interface InlineScript {
  name: string;    // e.g. "run.sh"
  content: string; // raw script text (UTF-8); base64-encoded at save/submit time
}

// DraftInputFile carries both the encoded payload (for save / submit)
// and the underlying File handle so we can show a per-file size /
// remove control without round-tripping through base64.
interface DraftInputFile extends TemplateInputFile {
  id: string;     // stable React key
  size: number;   // bytes (raw, before base64)
}

const STARTER_DRAFT: CustomDraft = {
  name: '',
  description: '',
  columns: [{ name: 'name' }],
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
  inputFiles: [],
  inlineScript: null,
};

// STARTER_INLINE_SCRIPT is what the editor prefills when the user
// first checks the "Include inline executable script" box. The
// shebang + `set -eu` is the safer-by-default minimum we want
// people to start from; they can edit freely.
const STARTER_INLINE_SCRIPT: InlineScript = {
  name: 'run.sh',
  content: `#!/bin/bash
set -eu

# Your job script. The submit-file body should set:
#   executable = run.sh
#   transfer_executable = true
echo "Hello from job $1@$(hostname)"
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
    columns: TemplateColumn[];
    contents: string;
    // Template's own default input files (vs. the per-batch files
    // the user drops below in section 3). Kept separate so the
    // submission step can label them in error messages and the user
    // can see why a file is in the upload list.
    templateInputFiles: TemplateInputFile[];
  }>(() => {
    if (mode === 'library' && selected) {
      return {
        name: selected.name,
        columns: selected.columns,
        contents: selected.contents,
        templateInputFiles: selected.input_files ?? [],
      };
    }
    // Custom mode: fold the inline executable script into the
    // input-files list. The body itself is kept in sync with the
    // script's filename by an effect below — by the time the user
    // submits, draft.contents already has executable=<script> and
    // transfer_executable=true, so there's nothing to layer on top
    // here. The inline-script feature stays a property of the
    // template editor.
    const draftFiles: TemplateInputFile[] = [...draft.inputFiles];
    if (draft.inlineScript && draft.inlineScript.name.trim() !== '') {
      draftFiles.push({
        name: draft.inlineScript.name.trim(),
        content: utf8ToBase64(draft.inlineScript.content),
      });
    }
    return {
      name: draft.name || '(new template)',
      columns: draft.columns,
      contents: draft.contents,
      templateInputFiles: draftFiles,
    };
  }, [mode, selected, draft]);

  // Column-name list cached for the table re-shape effect's dep array
  // (we want to react to add/remove/rename, not description tweaks).
  const columnNames = useMemo(
    () => active.columns.map((c) => c.name).join(''),
    [active.columns],
  );

  // --- Table section state ------------------------------------------
  const [rows, setRows] = useState<string[][]>([['']]);
  // tableSource = 'manual' is the original behavior (user fills in
  // the table by hand or pastes a CSV). 'upload' is the new mode
  // where the user picks a directory or tarball, and each contained
  // file becomes one row + one per-job input.
  const [tableSource, setTableSource] = useState<'manual' | 'upload'>(
    'manual',
  );
  // uploadFiles holds the per-job files contributed by 'upload' mode.
  // They're separate from the common-inputs `files` list so toggling
  // between modes is reversible — the upload set lives on, ready to
  // be re-applied if the user toggles back. A name collision with a
  // common-inputs entry is resolved at submit time, with the upload
  // entry winning (since it's bound to a specific job iteration).
  const [uploadFiles, setUploadFiles] = useState<DroppedFile[]>([]);

  // Re-shape rows whenever the active template's columns change. In
  // 'manual' mode we preserve the user's edits and only widen /
  // narrow the column count. The 'upload' mode's rows are computed
  // separately as a memo and overlaid below — keeping that
  // derivation OUT of the effect avoids the React 19 hooks lint's
  // "set-state-in-effect" warning while still giving us reactivity
  // when uploadFiles or columns change.
  useEffect(() => {
    setRows((prev) => reshapeRows(prev, active.columns));
    // active.columns identity changes whenever description changes
    // too; we only care about names. columnNames is a stable hash.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [columnNames]);

  // uploadRows: rows derived from the picked files in 'upload' mode.
  // Lives as a memo (not state) so the React 19 hooks lint doesn't
  // flag it, and so a change to uploadFiles is immediately reflected
  // without an extra render pass.
  const uploadRows = useMemo(
    () => rowsFromUploadFiles(uploadFiles, active.columns),
    // Same caveat as above re: columnNames being the right key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [uploadFiles, columnNames],
  );

  // --- Inputs section state -----------------------------------------
  const [files, setFiles] = useState<DroppedFile[]>([]);

  // --- Resources section state --------------------------------------
  // Whether the user has chosen to override what the template provides
  // (or fill in resources when the template is silent). When the
  // template already sets request_cpus/memory/disk we default to NOT
  // overriding — the template is the source of truth.
  const templateHasCoreResources = useMemo(
    () => bodyHasCoreResourceRequests(active.contents),
    [active.contents],
  );
  const [overrideResources, setOverrideResources] = useState(false);
  const [resources, setResources] = useState<ResourceRequest>(
    DEFAULT_RESOURCE_REQUEST,
  );

  // When the active template changes, prime resources from whatever it
  // declared (so the form is a faithful starting point if the user
  // *does* choose to override) and reset the override flag based on
  // whether the template already covers the core triple.
  useEffect(() => {
    setResources(readResourcesFromBody(active.contents));
    setOverrideResources(!templateHasCoreResources);
  }, [active.contents, templateHasCoreResources]);

  // First column's name; the per-job upload mode binds it to each
  // file's basename, so it's the variable that has to appear in
  // transfer_input_files for the upload to land in the right place.
  const firstColumnName = active.columns[0]?.name ?? '';

  // --- Live-edit effects --------------------------------------------
  //
  // These keep draft.contents (the textarea the user is looking at)
  // in sync with two affordances elsewhere in the page:
  //
  //   1. Inline executable script — toggling it on / renaming it
  //      rewrites `executable = …` and ensures
  //      `transfer_executable = true`.
  //   2. Upload-mode batch table — having uploaded files appends
  //      `$(<firstCol>)` to `transfer_input_files`.
  //
  // Both only fire in custom mode; library templates are read-only.
  // For the library + upload combination we surface a red warning
  // under the table instead of silently mutating someone else's
  // template.
  //
  // Each effect uses the functional setDraft form and bails out by
  // returning `prev` unchanged when the rewrite is a no-op, so we
  // don't spin React's render loop and don't fight the user when
  // they edit the textarea by hand.

  // We deliberately do NOT depend on draft.contents in the effect
  // below — the user may be typing in the Submit-file body textarea,
  // and rerunning the effect on every keystroke is wasteful (the
  // bailout-on-identity inside setDraft already keeps it safe). The
  // script object identity is the right trigger. The
  // set-state-in-effect rule is heuristically wrong about "synchronize
  // state to navigation / props"-style effects; we silence it on the
  // setDraft line.
  useEffect(() => {
    if (mode !== 'custom') return;
    const script = draft.inlineScript;
    if (!script || !script.name.trim()) return;
    const scriptName = script.name.trim();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDraft((prev) => {
      let next = setAttribute(prev.contents, 'executable', scriptName);
      next = setAttribute(next, 'transfer_executable', 'true');
      if (next === prev.contents) return prev;
      return { ...prev, contents: next };
    });
  }, [mode, draft.inlineScript]);

  useEffect(() => {
    if (mode !== 'custom') return;
    if (tableSource !== 'upload') return;
    if (uploadFiles.length === 0) return;
    if (!firstColumnName) return;
    const token = `$(${firstColumnName})`;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDraft((prev) => {
      const next = ensureTransferInput(prev.contents, token);
      if (next === prev.contents) return prev;
      return { ...prev, contents: next };
    });
  }, [mode, tableSource, uploadFiles.length, firstColumnName]);

  // Library mode + upload mode without a wired-up transfer_input_files:
  // surface a red warning under the table so the user knows the
  // upload won't reach the workers. We can't auto-edit a saved
  // template (it's not ours to mutate), so the next-best thing is
  // to make the broken-on-arrival case visible.
  const libraryUploadWarning = useMemo<string | null>(() => {
    if (mode !== 'library') return null;
    if (tableSource !== 'upload') return null;
    if (uploadFiles.length === 0) return null;
    if (!firstColumnName) return null;
    const token = `$(${firstColumnName})`;
    const tif = getAttribute(active.contents, 'transfer_input_files') ?? '';
    const tokens = tif.split(/[\s,]+/).filter(Boolean);
    if (tokens.includes(token)) return null;
    return `This template's transfer_input_files does not reference ${token}. The per-job upload files won't be sent to the workers — pick a different template, or save a custom one that adds ${token} to transfer_input_files.`;
  }, [mode, tableSource, uploadFiles.length, firstColumnName, active.contents]);

  // --- Submit -------------------------------------------------------
  const submit = useMutation({
    mutationFn: async () => {
      // If the user filled in (or kept) the resources widget, those
      // values overwrite whatever the template body had. If the
      // template already provides resources and the user opted not to
      // override, leave the body alone.
      let effectiveContents = overrideResources
        ? applyResourcesToBody(active.contents, resources)
        : active.contents;

      // The auto-wiring of executable= / transfer_executable= and of
      // transfer_input_files for upload mode now happens *live* on
      // draft.contents via effects further up — see the
      // useEffect blocks that watch draft.inlineScript and the
      // (tableSource, uploadFiles, firstColumnName) tuple. The active
      // memo passes draft.contents through unchanged in custom mode,
      // so by the time we get here those edits are already baked in.
      // (Library mode is read-only; the effect-and-warning split
      // means we surface a red warning under the table instead.)

      // Use uploadRows when the table is sourced from a directory /
      // tarball — the manual `rows` state is preserved across mode
      // toggles and would be stale.
      const effectiveRows = tableSource === 'upload' ? uploadRows : rows;
      const body = buildSubmitFile(
        effectiveContents,
        active.columns.map((c) => c.name),
        effectiveRows,
      );
      const submitted = await api.jobs.submit(body);

      // Common files: template default attachments + the user's
      // dropzone uploads + any inline executable script. These go to
      // every job in the batch — the spool is per-proc on the schedd
      // side, so each proc.subproc directory needs its own copy.
      const commonFiles = await mergeTemplateAndUserFiles(
        active.templateInputFiles,
        files,
      );

      // Upload mode: each row is bound to exactly one file from the
      // picked directory / tarball, and submitted.job_ids[i] is that
      // row's job. Fan out — every job gets the common set plus its
      // own uploadFiles[i] entry. Without this fan-out the schedd
      // (correctly) holds procs > 0 with "No such file or directory"
      // because the per-job file never reached its spool, and even
      // proc 0 only spools the file whose basename happens to match
      // its TransferInput.
      const isUploadMode =
        tableSource === 'upload' && uploadFiles.length > 0;

      const jobIDs = submitted.job_ids;
      for (let i = 0; i < jobIDs.length; i++) {
        let perJob = commonFiles;
        if (isUploadMode && uploadFiles[i]) {
          // Drop any common-files entry whose name collides with the
          // per-job file — the per-job upload binds to this row's
          // specific iteration, so it should win.
          const uf = uploadFiles[i];
          perJob = [
            ...commonFiles.filter((f) => f.name !== uf.name),
            { name: uf.name, file: uf.file, executable: uf.executable },
          ];
        }
        if (perJob.length === 0) continue;
        await api.jobs.uploadInputs(jobIDs[i], perJob);
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
    mutationFn: () => {
      // The inline-script editor's contents are a peer of the
      // attached input files. Persist them as one of the
      // template's input_files so a later round-trip (load
      // saved template → edit → re-save) reproduces the same
      // attachment list. The active.templateInputFiles memo above
      // already does this fold for the runtime path; doing it
      // again here keeps the save mutation's data shape obvious
      // without depending on that memo's recompute timing.
      const files: TemplateInputFile[] = draft.inputFiles.map(
        ({ name, content }) => ({ name, content }),
      );
      if (draft.inlineScript && draft.inlineScript.name.trim() !== '') {
        files.push({
          name: draft.inlineScript.name.trim(),
          content: utf8ToBase64(draft.inlineScript.content),
        });
      }
      // draft.contents already has the executable= /
      // transfer_executable= / transfer_input_files edits applied
      // (the live-edit effects keep it in sync with the inline
      // script and upload state), so we save it verbatim.
      return api.templates.save({
        name: draft.name,
        description: draft.description,
        columns: draft.columns,
        contents: draft.contents,
        input_files: files,
      });
    },
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
      // Switch to library mode and select the new entry.
      setMode('library');
      setSelectedID(saved.id);
    },
  });

  // The "rows" state is per-mode; pick the right one for the
  // disabled check so toggling into upload mode (which clears the
  // user's edits but preserves the manual rows in state) doesn't
  // silently re-enable the button on stale data.
  const effectiveRowsForGate =
    tableSource === 'upload' ? uploadRows : rows;
  const submitDisabled =
    submit.isPending ||
    !active.contents.trim() ||
    effectiveRowsForGate.length === 0 ||
    effectiveRowsForGate.some((r) => r.every((c) => c.trim() === ''));

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
        // In 'upload' mode the rows are derived from the picked
        // files and we don't let the user edit them — every change
        // comes from re-picking. In 'manual' mode the parent's
        // setRows handles user edits as before.
        rows={tableSource === 'upload' ? uploadRows : rows}
        setRows={setRows}
        source={tableSource}
        setSource={setTableSource}
        uploadFiles={uploadFiles}
        setUploadFiles={setUploadFiles}
      />

      {libraryUploadWarning && (
        <div
          role="alert"
          className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          ⚠ {libraryUploadWarning}
        </div>
      )}

      <InputsSection files={files} setFiles={setFiles} disabled={submit.isPending} />

      <ResourcesSection
        templateHasResources={bodyHasResourceRequests(active.contents)}
        templateHasCoreResources={templateHasCoreResources}
        override={overrideResources}
        setOverride={setOverrideResources}
        resources={resources}
        setResources={setResources}
      />

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
          {submit.isPending ? 'Submitting…' : `Submit batch (${effectiveRowsForGate.length} job${effectiveRowsForGate.length === 1 ? '' : 's'})`}
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
                          key={c.name}
                          title={c.description ?? undefined}
                          className="ml-1 rounded bg-white border border-gray-200 px-1 py-0.5"
                        >
                          {c.name}
                        </code>
                      ))
                    )}
                  </div>
                  {selected.input_files && selected.input_files.length > 0 && (
                    <div className="text-gray-600">
                      Default input files:{' '}
                      {selected.input_files.map((f) => (
                        <code
                          key={f.name}
                          className="ml-1 rounded bg-white border border-gray-200 px-1 py-0.5"
                        >
                          {f.name}
                        </code>
                      ))}
                    </div>
                  )}
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
          templates={templates}
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
  templates,
}: {
  draft: CustomDraft;
  setDraft: (d: CustomDraft) => void;
  onSave: () => void;
  saveState: { isPending: boolean; error: unknown };
  templates: Template[];
}) {
  const canSave = draft.name.trim() !== '' && draft.contents.trim() !== '';

  // Embedded resources widget. Toggling it on patches the body with
  // the structured request_* lines so the saved template carries them
  // through the YAML round-trip. Reading from the body keeps the
  // widget in sync if the user edits the textarea directly.
  const [includeResources, setIncludeResources] = useState(() =>
    bodyHasResourceRequests(draft.contents),
  );
  const resources = useMemo(
    () => readResourcesFromBody(draft.contents),
    [draft.contents],
  );

  const setResourceFields = (next: ResourceRequest) => {
    setDraft({ ...draft, contents: applyResourcesToBody(draft.contents, next) });
  };

  const toggleResources = (on: boolean) => {
    setIncludeResources(on);
    if (on && !bodyHasResourceRequests(draft.contents)) {
      // Seed with defaults so the user has something concrete to tweak.
      setDraft({
        ...draft,
        contents: applyResourcesToBody(draft.contents, DEFAULT_RESOURCE_REQUEST),
      });
    }
  };

  // Clone-from-existing replaces the draft wholesale with a copy of
  // an existing template (built-in / global / user). Caller picks
  // from the same select as the library mode would offer; the
  // resulting draft's name gets a "(clone)" suffix so the user
  // doesn't accidentally clobber the original on Save (which keys on
  // (owner, id) and would refuse for read-only sources anyway).
  const cloneFrom = async (id: string) => {
    const tpl = templates.find((t) => t.id === id);
    if (!tpl) return;
    const cloned: DraftInputFile[] = (tpl.input_files ?? []).map((f) => ({
      id: makeFileId(),
      name: f.name,
      content: f.content,
      size: base64DecodedSize(f.content),
    }));
    setDraft({
      name: `${tpl.name} (clone)`,
      description: tpl.description ?? '',
      columns: tpl.columns.map((c) => ({ ...c })),
      contents: tpl.contents,
      inputFiles: cloned,
      // Cloning a library template never seeds the inline-script
      // editor — the source's input_files might include something
      // that LOOKS like a script but the user didn't write it inline
      // here. Cleaner to leave the editor empty so the user opts in
      // explicitly if they want to convert.
      inlineScript: null,
    });
  };

  return (
    <div className="space-y-3 mt-3">
      {/* Clone-from-existing — appears at the top so it's the first
          thing users see when they switch to "Write new template". */}
      {templates.length > 0 && (
        <CloneFromPicker templates={templates} onClone={cloneFrom} />
      )}

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
        <Field label="Description (optional)">
          <input
            type="text"
            value={draft.description}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })}
            placeholder="One-line description"
            className="w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
          />
        </Field>
      </div>

      <Field label="Columns">
        <ColumnEditor
          columns={draft.columns}
          setColumns={(cols) => setDraft({ ...draft, columns: cols })}
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

      <InlineScriptEditor
        script={draft.inlineScript}
        setScript={(s) => setDraft({ ...draft, inlineScript: s })}
      />

      <Field label="Default input files (optional)">
        <TemplateInputFilesEditor
          files={draft.inputFiles}
          setFiles={(fs) => setDraft({ ...draft, inputFiles: fs })}
        />
      </Field>

      <div className="rounded border border-gray-200 bg-gray-50 p-3 space-y-3">
        <label className="flex items-center gap-2 text-sm text-gray-700">
          <input
            type="checkbox"
            checked={includeResources}
            onChange={(e) => toggleResources(e.target.checked)}
            className="rounded border-gray-300"
          />
          Bake resource requests into this template
        </label>
        {includeResources && (
          <ResourceRequestPanel value={resources} onChange={setResourceFields} />
        )}
        {!includeResources && bodyHasResourceRequests(draft.contents) && (
          <p className="text-xs text-amber-700">
            The textarea still has request_* lines from a previous edit.
            Toggle this on to manage them via the widget, or remove them
            by hand.
          </p>
        )}
      </div>

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

// CloneFromPicker is a small one-shot select that triggers cloneFrom
// on change. Sticky-empty (resets to the placeholder option) so the
// user can clone twice in a row without a manual reset.
function CloneFromPicker({
  templates,
  onClone,
}: {
  templates: Template[];
  onClone: (id: string) => void;
}) {
  return (
    <div className="rounded border border-dashed border-gray-300 bg-gray-50 px-3 py-2 text-xs flex items-center gap-2">
      <span className="text-gray-600 shrink-0">Start from a copy of:</span>
      <select
        defaultValue=""
        onChange={(e) => {
          const v = e.target.value;
          if (!v) return;
          onClone(v);
          e.target.value = '';
        }}
        className="flex-1 min-w-0 rounded border border-gray-300 bg-white px-2 py-1"
      >
        <option value="" disabled>
          (pick a template to clone…)
        </option>
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
    </div>
  );
}

// ColumnEditor renders one row per column with a name input, an
// optional description (rendered as the table-header help text), and
// a remove button. A trailing row with a "+" button appends a new
// column. Names are validated against the same HTCondor-macro regex
// the server uses; bad names get a red border and tooltip but don't
// block typing.
function ColumnEditor({
  columns,
  setColumns,
}: {
  columns: TemplateColumn[];
  setColumns: (cols: TemplateColumn[]) => void;
}) {
  const [pendingName, setPendingName] = useState('');
  const [pendingDesc, setPendingDesc] = useState('');

  const addPending = () => {
    const name = pendingName.trim();
    if (!name) return;
    if (columns.some((c) => c.name === name)) return; // dedupe silently
    setColumns([
      ...columns,
      { name, description: pendingDesc.trim() || undefined },
    ]);
    setPendingName('');
    setPendingDesc('');
  };

  return (
    <div className="space-y-1">
      {columns.length === 0 && (
        <p className="text-xs text-gray-500">
          No columns yet — add one below to bind a $(name) reference in the
          submit body.
        </p>
      )}
      {columns.map((col, i) => (
        <div key={i} className="flex items-center gap-2">
          <input
            type="text"
            value={col.name}
            onChange={(e) => {
              const next = columns.map((c, j) =>
                j === i ? { ...c, name: e.target.value } : c,
              );
              setColumns(next);
            }}
            placeholder="column_name"
            className={`w-40 rounded border px-2 py-1 font-mono text-sm ${
              isValidColumnName(col.name)
                ? 'border-gray-300'
                : 'border-red-300'
            }`}
            title={
              isValidColumnName(col.name)
                ? undefined
                : 'Must match [A-Za-z_][A-Za-z0-9_]*'
            }
          />
          <input
            type="text"
            value={col.description ?? ''}
            onChange={(e) => {
              const next = columns.map((c, j) =>
                j === i ? { ...c, description: e.target.value } : c,
              );
              setColumns(next);
            }}
            placeholder="description (optional, shown as help text)"
            className="flex-1 min-w-0 rounded border border-gray-300 px-2 py-1 text-sm"
          />
          <button
            type="button"
            onClick={() => setColumns(columns.filter((_, j) => j !== i))}
            className="text-xs text-gray-400 hover:text-red-600"
            title="Remove column"
          >
            ×
          </button>
        </div>
      ))}

      {/* Add-row, mirrors the per-column row visually. Press Enter in
          the name field to add — saves a click on the most common
          flow. */}
      <div className="flex items-center gap-2 pt-1">
        <input
          type="text"
          value={pendingName}
          onChange={(e) => setPendingName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              addPending();
            }
          }}
          placeholder="new column name"
          className="w-40 rounded border border-gray-300 px-2 py-1 font-mono text-sm"
        />
        <input
          type="text"
          value={pendingDesc}
          onChange={(e) => setPendingDesc(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              addPending();
            }
          }}
          placeholder="description (optional)"
          className="flex-1 min-w-0 rounded border border-gray-300 px-2 py-1 text-sm"
        />
        <button
          type="button"
          onClick={addPending}
          disabled={pendingName.trim() === ''}
          className="rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          title="Add column"
        >
          + Add
        </button>
      </div>
    </div>
  );
}

// TemplateInputFilesEditor handles the "default attachments shipped
// with this template" list. Files are read into base64 immediately
// so the saved template carries them verbatim; per-file 1 MiB cap
// is enforced client-side (server enforces the same).
// InlineScriptEditor renders the "I want to write the executable
// script right here" affordance. Belongs to the custom-template
// editor — the script is part of the template, so it's only
// available when the user is writing a new template (library
// templates are read-only).
//
// State is owned by the parent CustomDraft so the script round-trips
// through save / load / submit unchanged. The editor serializes the
// script as one of the template's input_files at save and submit
// time. A SubmitPage-level effect keeps the parent's draft.contents
// in sync — toggling the script on, or renaming it, immediately
// rewrites the Submit-file body's `executable = …` and
// `transfer_executable = true` lines so the textarea always reflects
// what will actually be submitted.
//
// The executable bit is set on the receiving job by the existing
// filename-extension heuristic in mergeTemplateAndUserFiles
// (`.sh`/`.py`/etc. → +x). Default to `run.sh` so the heuristic
// catches it; users who pick a non-extension name would need to
// arrange the +x another way (e.g. via a wrapper script).
function InlineScriptEditor({
  script,
  setScript,
}: {
  script: InlineScript | null;
  setScript: (s: InlineScript | null) => void;
}) {
  return (
    <div className="rounded border border-gray-200 bg-gray-50 p-3 space-y-3">
      <label className="flex items-center gap-2 text-sm text-gray-700">
        <input
          type="checkbox"
          checked={script !== null}
          onChange={(e) => setScript(e.target.checked ? STARTER_INLINE_SCRIPT : null)}
          className="rounded border-gray-300"
        />
        Write executable script inline
      </label>

      {script && (
        <div className="space-y-2">
          <Field label="Script filename">
            <input
              type="text"
              value={script.name}
              onChange={(e) => setScript({ ...script, name: e.target.value })}
              placeholder="run.sh"
              className="w-48 rounded border border-gray-300 px-2 py-1 font-mono text-sm"
            />
            <p className="mt-1 text-xs text-gray-500">
              Attached as a default input file. The Submit-file body
              above gets <code>executable = {script.name || 'run.sh'}</code>{' '}
              and <code>transfer_executable = true</code> updated
              automatically as you edit this — no need to maintain
              those lines yourself. Names ending in .sh / .py / .pl /
              .rb get the executable bit set when the job is
              submitted.
            </p>
          </Field>
          <Field label="Script content">
            <textarea
              value={script.content}
              onChange={(e) => setScript({ ...script, content: e.target.value })}
              spellCheck={false}
              className="w-full h-48 rounded border border-gray-300 px-3 py-2 font-mono text-xs"
            />
          </Field>
        </div>
      )}
    </div>
  );
}

function TemplateInputFilesEditor({
  files,
  setFiles,
}: {
  files: DraftInputFile[];
  setFiles: (files: DraftInputFile[]) => void;
}) {
  const [error, setError] = useState<string | null>(null);

  const addFiles = async (incoming: FileList | File[]) => {
    setError(null);
    const list = Array.from(incoming);
    const next: DraftInputFile[] = [];
    const seen = new Set(files.map((f) => f.name));
    for (const file of list) {
      if (file.size > MAX_TEMPLATE_INPUT_FILE_BYTES) {
        setError(
          `${file.name} is ${humanSize(file.size)}; the per-file cap is ${humanSize(MAX_TEMPLATE_INPUT_FILE_BYTES)}.`,
        );
        continue;
      }
      let name = file.name;
      let i = 1;
      while (seen.has(name)) {
        const dot = file.name.lastIndexOf('.');
        name =
          dot > 0
            ? `${file.name.slice(0, dot)} (${i})${file.name.slice(dot)}`
            : `${file.name} (${i})`;
        i++;
      }
      seen.add(name);
      const buf = await file.arrayBuffer();
      next.push({
        id: makeFileId(),
        name,
        content: arrayBufferToBase64(buf),
        size: file.size,
      });
    }
    setFiles([...files, ...next]);
  };

  return (
    <div className="space-y-2">
      <div className="rounded border border-dashed border-gray-300 bg-gray-50 px-3 py-3 text-xs">
        <label className="cursor-pointer text-gray-700">
          <span className="rounded border border-gray-300 bg-white px-2 py-1 hover:bg-gray-100">
            Attach files…
          </span>
          <input
            type="file"
            multiple
            className="sr-only"
            onChange={(e) => {
              if (e.target.files?.length) {
                addFiles(e.target.files).catch((err) =>
                  setError(err instanceof Error ? err.message : String(err)),
                );
              }
              e.target.value = '';
            }}
          />
        </label>
        <span className="ml-2 text-gray-500">
          Up to {humanSize(MAX_TEMPLATE_INPUT_FILE_BYTES)} per file. These ship
          with the template — the submit page sends them alongside any
          per-batch files dropped below.
        </span>
      </div>

      {error && <p className="text-xs text-red-700">{error}</p>}

      {files.length > 0 && (
        <ul className="rounded border border-gray-200 bg-white divide-y divide-gray-100 text-sm">
          {files.map((f) => (
            <li key={f.id} className="flex items-center gap-2 px-3 py-2">
              <input
                value={f.name}
                onChange={(e) =>
                  setFiles(
                    files.map((x) =>
                      x.id === f.id ? { ...x, name: e.target.value } : x,
                    ),
                  )
                }
                className="flex-1 min-w-0 rounded border border-transparent bg-transparent px-1 py-0.5 font-mono text-xs hover:border-gray-200 focus:border-gray-300 focus:outline-none"
              />
              <span className="text-xs text-gray-400 shrink-0">
                {humanSize(f.size)}
              </span>
              <button
                type="button"
                onClick={() => setFiles(files.filter((x) => x.id !== f.id))}
                className="text-xs text-red-600 hover:text-red-800 shrink-0"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function isValidColumnName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function makeFileId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// utf8ToBase64 encodes a UTF-8 string for the input-file `content`
// field on the template-save / template-input wire shape, which is
// always base64. The TextEncoder + chunked btoa avoids both the
// argument-count limit on apply() and the latin-1-only restriction
// that bites a naive `btoa(s)` call when the script contains
// multibyte characters (emoji, CJK, etc. — rare in shell scripts but
// not impossible).
function utf8ToBase64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  return arrayBufferToBase64(bytes.buffer as ArrayBuffer);
}

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  // chunk to avoid hitting the argument-count limit for large files
  // (apply() with > ~100k args is unreliable across browsers).
  const CHUNK = 0x8000;
  let bin = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

function base64DecodedSize(b64: string): number {
  // Length without trailing '=' padding × 3/4 is the byte count.
  const padding = (b64.endsWith('==') && 2) || (b64.endsWith('=') && 1) || 0;
  return Math.floor((b64.length * 3) / 4) - padding;
}

function base64ToFile(b64: string, name: string): File {
  // Reverse of arrayBufferToBase64 with chunking.
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new File([bytes], name);
}

// rowsFromUploadFiles synthesizes the batch table from the list of
// files contributed by step-2 "from upload" mode. The first column
// of the active template gets the file's basename; any additional
// columns are filled with empty strings (the user can switch back to
// manual mode and edit them, or use a single-column template that
// fits the upload pattern). Empty input → one empty row, mirroring
// the manual-mode initial state.
function rowsFromUploadFiles(
  files: DroppedFile[],
  cols: TemplateColumn[],
): string[][] {
  if (cols.length === 0) {
    // Zero-column template: one row per file, no cells. Submit
    // builder treats this as a fixed-job template and emits a bare
    // `queue` line, so each "row" is one job.
    return files.length === 0 ? [[]] : files.map(() => []);
  }
  if (files.length === 0) {
    // Toggling into upload mode before picking files: keep one
    // empty row so the table renders with the column headers.
    return [cols.map(() => '')];
  }
  return files.map((f) => {
    const row = cols.map(() => '');
    row[0] = f.name; // first column gets the filename
    return row;
  });
}

// mergeTemplateAndUserFiles turns the template's default attachments
// (base64 + name) into File objects, then merges with the user's
// per-batch drops. When a name collides, the user's drop wins —
// most-recent intent.
async function mergeTemplateAndUserFiles(
  templateFiles: TemplateInputFile[],
  userFiles: DroppedFile[],
): Promise<{ name: string; file: File; executable: boolean }[]> {
  const userByName = new Map(userFiles.map((f) => [f.name, f]));
  const out: { name: string; file: File; executable: boolean }[] = [];
  for (const tf of templateFiles) {
    if (userByName.has(tf.name)) continue; // user override wins
    out.push({
      name: tf.name,
      file: base64ToFile(tf.content, tf.name),
      // Heuristic: shell scripts attached via templates almost
      // always need exec bit. Users who want different behavior can
      // add the file as a per-batch upload (which round-trips
      // through Dropzone where they can toggle the checkbox).
      executable: /\.(sh|py|pl|rb)$/i.test(tf.name) || tf.name === 'run',
    });
  }
  for (const uf of userFiles) {
    out.push({ name: uf.name, file: uf.file, executable: uf.executable });
  }
  return out;
}

// ----------------------------------------------------------------------
// Table section: one row per job. Column headers come from the active
// template; the user fills cells.
// ----------------------------------------------------------------------

function TableSection({
  columns,
  rows,
  setRows,
  source,
  setSource,
  uploadFiles,
  setUploadFiles,
}: {
  columns: TemplateColumn[];
  rows: string[][];
  setRows: (r: string[][]) => void;
  source: 'manual' | 'upload';
  setSource: (s: 'manual' | 'upload') => void;
  uploadFiles: DroppedFile[];
  setUploadFiles: (f: DroppedFile[]) => void;
}) {
  const columnNames = columns.map((c) => c.name);
  return (
    <SectionCard
      title="2. Table"
      subtitle={
        columns.length === 0
          ? 'This template has no variable columns; one row = one job.'
          : source === 'upload'
            ? `One job per file from the upload. ${uploadFiles.length} file${uploadFiles.length === 1 ? '' : 's'} loaded.`
            : `Column headers come from the template. ${rows.length} row${rows.length === 1 ? '' : 's'} = ${rows.length} job${rows.length === 1 ? '' : 's'}.`
      }
    >
      {/* Source toggle: manual table vs. directory/tarball upload.
          Visible only when there's at least one column to fill —
          a zero-column template is a fixed single job and "from
          upload" doesn't make sense there. */}
      {columns.length > 0 && (
        <div className="mb-3 inline-flex rounded-md border border-gray-300 bg-white p-0.5 text-sm">
          <ModeButton active={source === 'manual'} onClick={() => setSource('manual')}>
            Manual table
          </ModeButton>
          <ModeButton active={source === 'upload'} onClick={() => setSource('upload')}>
            From directory / tarball
          </ModeButton>
        </div>
      )}

      {columns.length === 0 ? (
        <div className="text-sm text-gray-500">
          Single fixed job. Click <em>Submit batch</em> to send 1 job.
        </div>
      ) : source === 'upload' ? (
        <UploadSource
          firstColumn={columnNames[0]}
          uploadFiles={uploadFiles}
          setUploadFiles={setUploadFiles}
        />
      ) : (
        <div className="space-y-2">
          <CSVImporter columns={columnNames} setRows={setRows} />
          <div className="overflow-x-auto rounded border border-gray-200 bg-white">
            <table className="min-w-full text-sm border-collapse">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-2 py-1 w-10 text-right text-gray-400 border-b border-gray-200">
                    #
                  </th>
                  {columns.map((c) => (
                    <th
                      key={c.name}
                      className="px-2 py-1 font-mono border-b border-l border-gray-200"
                      // Description (when set on the template) becomes
                      // the column header's tooltip — that's the
                      // user-facing payoff of the description field.
                      title={c.description ?? undefined}
                    >
                      <span className="inline-flex items-center gap-1">
                        {c.name}
                        {c.description && (
                          <span
                            className="cursor-help text-[10px] font-normal normal-case text-gray-400"
                            aria-hidden
                          >
                            ⓘ
                          </span>
                        )}
                      </span>
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

// UploadSource is the step-2 "from directory / tarball" mode body.
// User picks a folder (via webkitdirectory) or a .tar / .tar.gz file
// and the component:
//   - Enumerates the contained files (skipping directories and tar
//     metadata entries).
//   - Pushes one DroppedFile per entry up to the parent's
//     uploadFiles state, using the basename as the file's `name`.
//   - The parent's effect synthesizes one table row per file with
//     the basename in the first column. The submit body should
//     reference the first column as $(<columnName>).
//
// Why basename, not full path: each per-job file is a transfer-input
// to that one iteration. Job sandboxes are flat; the executable
// inside sees the file at its basename. Preserving directory
// structure would require materialising it on the worker, which the
// HTCondor input-transfer flow doesn't do for us.
function UploadSource({
  firstColumn,
  uploadFiles,
  setUploadFiles,
}: {
  firstColumn: string;
  uploadFiles: DroppedFile[];
  setUploadFiles: (f: DroppedFile[]) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  const acceptDirectory = async (fileList: FileList) => {
    setError(null);
    setWarnings([]);
    const incoming: DroppedFile[] = [];
    const seen = new Set<string>();
    for (const f of Array.from(fileList)) {
      // FileList from a webkitdirectory input includes nested files
      // with relative paths via webkitRelativePath. Take the basename
      // for both the upload key and the table cell — see the
      // "why basename" note above.
      const base = basenameOf(f.name);
      if (!base || seen.has(base)) continue;
      seen.add(base);
      incoming.push({ id: makeFileId(), name: base, file: f, executable: false });
    }
    if (incoming.length === 0) {
      setError('Directory contained no files.');
      return;
    }
    setUploadFiles(incoming);
  };

  const acceptTarball = async (file: File) => {
    setError(null);
    setWarnings([]);
    try {
      const { readTarball } = await import('@/lib/tarball');
      const result = await readTarball(file);
      if (result.entries.length === 0) {
        setError('Tarball contained no regular files.');
        return;
      }
      const seen = new Set<string>();
      const incoming: DroppedFile[] = [];
      for (const entry of result.entries) {
        const base = basenameOf(entry.name);
        if (!base || seen.has(base)) continue;
        seen.add(base);
        // Wrap the entry's Blob in a File so the upload pipeline
        // (which calls `form.append("input", file, name)`) can
        // read it. The basename is what HTCondor sees in the
        // sandbox, which matches what the synthesized $(file)
        // expansion will reference.
        incoming.push({
          id: makeFileId(),
          name: base,
          file: new File([entry.content], base),
          executable: false,
        });
      }
      setUploadFiles(incoming);
      if (result.warnings.length > 0) {
        setWarnings(result.warnings);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="space-y-3">
      <div className="rounded border border-dashed border-gray-300 bg-gray-50 p-4 space-y-3">
        <div className="text-xs text-gray-700">
          Pick a directory or a .tar / .tar.gz archive. Each file becomes
          one job, with{' '}
          <code className="bg-white border border-gray-200 px-1 py-0.5 rounded">
            $({firstColumn || 'file'})
          </code>{' '}
          bound to the file&apos;s basename.{' '}
          <code className="bg-white border border-gray-200 px-1 py-0.5 rounded">
            transfer_input_files
          </code>{' '}
          is wired up automatically — the submit body gets{' '}
          <code className="bg-white border border-gray-200 px-1 py-0.5 rounded">
            $({firstColumn || 'file'})
          </code>{' '}
          appended (or set, if the attribute is missing) so each job
          picks up its own file.
        </div>

        <div className="flex flex-wrap gap-2 text-xs">
          <label className="cursor-pointer rounded border border-gray-300 bg-white px-3 py-1.5 hover:bg-gray-100">
            Pick directory…
            <input
              type="file"
              // webkitdirectory + multiple is the de-facto cross-
              // browser idiom for directory pickers. Chrome,
              // Firefox, Safari, and Edge all support it. The
              // ts-expect-error keeps tsc happy without a
              // tsconfig DOM lib bump.
              // @ts-expect-error -- webkitdirectory isn't in lib.dom yet
              webkitdirectory=""
              directory=""
              multiple
              className="sr-only"
              onChange={(e) => {
                if (e.target.files?.length) {
                  acceptDirectory(e.target.files).catch((err) =>
                    setError(err instanceof Error ? err.message : String(err)),
                  );
                }
                e.target.value = '';
              }}
            />
          </label>
          <label className="cursor-pointer rounded border border-gray-300 bg-white px-3 py-1.5 hover:bg-gray-100">
            Pick tarball…
            <input
              type="file"
              accept=".tar,.tar.gz,.tgz,application/x-tar,application/gzip"
              className="sr-only"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) {
                  acceptTarball(f).catch((err) =>
                    setError(err instanceof Error ? err.message : String(err)),
                  );
                }
                e.target.value = '';
              }}
            />
          </label>
          {uploadFiles.length > 0 && (
            <button
              type="button"
              onClick={() => {
                setUploadFiles([]);
                setError(null);
                setWarnings([]);
              }}
              className="rounded border border-gray-300 bg-white px-3 py-1.5 text-red-700 hover:bg-red-50"
            >
              Clear ({uploadFiles.length})
            </button>
          )}
        </div>

        {error && <p className="text-xs text-red-700">{error}</p>}
        {warnings.length > 0 && (
          <details className="text-[11px] text-amber-800">
            <summary className="cursor-pointer">
              {warnings.length} parser warning{warnings.length === 1 ? '' : 's'}
            </summary>
            <ul className="mt-1 ml-4 list-disc space-y-0.5">
              {warnings.slice(0, 50).map((w, i) => (
                <li key={i}>{w}</li>
              ))}
              {warnings.length > 50 && (
                <li className="text-gray-500">
                  …and {warnings.length - 50} more
                </li>
              )}
            </ul>
          </details>
        )}
      </div>

      {uploadFiles.length > 0 && (
        <div className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 bg-gray-50 px-3 py-1.5 text-xs text-gray-600">
            {uploadFiles.length} file{uploadFiles.length === 1 ? '' : 's'} = {uploadFiles.length} job{uploadFiles.length === 1 ? '' : 's'}
          </div>
          <ul className="divide-y divide-gray-100 max-h-48 overflow-auto">
            {uploadFiles.slice(0, 200).map((f) => (
              <li key={f.name} className="flex items-center gap-2 px-3 py-1 text-xs font-mono">
                <span className="text-gray-400 tabular-nums w-12">
                  {humanSize(f.file.size)}
                </span>
                <span className="truncate">{f.name}</span>
              </li>
            ))}
            {uploadFiles.length > 200 && (
              <li className="px-3 py-1 text-[11px] text-gray-500">
                …and {uploadFiles.length - 200} more
              </li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

// basenameOf returns the trailing path component, treating both
// '/' and '\' as separators. Used for tarball entries (which use
// '/') and webkitdirectory FileList entries (browser-dependent
// separators).
function basenameOf(p: string): string {
  if (p === '') return '';
  // Strip trailing slashes (e.g. directory entries).
  let s = p;
  while (s.endsWith('/') || s.endsWith('\\')) s = s.slice(0, -1);
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i < 0 ? s : s.slice(i + 1);
}

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
      title="3. Common Inputs"
      subtitle="Files attached to every job in the batch. (Per-job files come from step 2's upload mode if you used it.)"
    >
      <Dropzone files={files} onChange={setFiles} disabled={disabled} />
    </SectionCard>
  );
}

// ----------------------------------------------------------------------
// Resources section: Step 4. Optional when the template already provides
// the core request_cpus / request_memory / request_disk triple — the
// user can opt to override; otherwise required so the schedd has
// resource requests to plan the match against.
// ----------------------------------------------------------------------

function ResourcesSection({
  templateHasResources,
  templateHasCoreResources,
  override,
  setOverride,
  resources,
  setResources,
}: {
  templateHasResources: boolean;
  templateHasCoreResources: boolean;
  override: boolean;
  setOverride: (v: boolean) => void;
  resources: ResourceRequest;
  setResources: (r: ResourceRequest) => void;
}) {
  const subtitle = templateHasCoreResources
    ? 'The template already declares request_cpus, request_memory, and request_disk. Skip this step to use what it provides, or override.'
    : 'The template does not declare resource requests. Pick CPU, memory, disk (and GPU if needed) — these get appended to the submit-file body.';
  return (
    <SectionCard title="4. Resources" subtitle={subtitle}>
      {templateHasCoreResources && (
        <label className="mb-3 flex items-center gap-2 text-sm text-gray-700">
          <input
            type="checkbox"
            checked={override}
            onChange={(e) => setOverride(e.target.checked)}
            className="rounded border-gray-300"
          />
          Override the template&apos;s resource requests
        </label>
      )}
      {override ? (
        <ResourceRequestPanel value={resources} onChange={setResources} />
      ) : (
        <p className="text-xs text-gray-500">
          {templateHasResources
            ? 'Using the values from the template body.'
            : 'No resource requests will be sent. The schedd will fall back to its pool-wide defaults.'}
        </p>
      )}
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

function reshapeRows(prev: string[][], cols: TemplateColumn[]): string[][] {
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
