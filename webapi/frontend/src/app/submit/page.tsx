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
//
// === LLM AGENT INTEGRATION ===
// The chat assistant rendered at the bottom is page-aware and hits
// /api/v1/chat with `page: "submit"`. The system-prompt suffix and
// the tool allowlist for this page live server-side at
// httpserver/handlers_chat_tools.go (constants `submitPageInstructions`
// and helpers `toolSetTemplateBody`, `toolSetInlineScript`, etc.).
//
// KEEP THESE IN SYNC: if a section is renamed/removed, a state field a
// tool writes to is restructured, or the submit flow changes shape,
// update the matching server-side description and tool dispatch logic
// so the LLM doesn't hallucinate UI affordances. The submit button is
// human-only by design — there is intentionally no submit_job tool.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
import { ChatPanel, type ToolHandler } from '@/components/ChatPanel';
import { Dropzone, type DroppedFile } from '@/components/Dropzone';
import {
  ResourceRequestPanel,
  DEFAULT_RESOURCE_REQUEST,
  type ResourceRequest,
} from '@/components/ResourceRequest';
import {
  applyResourcesToBody,
  bodyHasCoreResourceRequests,
  bodyHasQueueLine,
  bodyHasResourceRequests,
  ensureTransferInput,
  getAttribute,
  readResourcesFromBody,
  setAttribute,
  type ResourceFieldMask,
} from '@/lib/submitFile';

type TemplateMode = 'library' | 'custom';

// TableSource picks how the per-job parameters are sourced.
//   manual — user fills the rendered table (or pastes CSV)
//   count  — no per-job parameters; submit N copies (HTCondor `queue N`).
//            Use when each job needs only ProcId-based differentiation.
//   upload — directory/tarball mode; one row per contained file.
type TableSource = 'manual' | 'count' | 'upload';

const MAX_TABLE_COUNT = 10000;

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
  // Additional inline files that ship in the job's sandbox alongside
  // the wrapper script. Used for the "wrapper.sh + analyze.py"
  // pattern: the wrapper is the executable (mode 0755 via
  // inlineScript above), each entry here is a payload file (mode
  // 0644). Distinct from `inputFiles` because these are co-edited in
  // the chat UI rather than dropped from the user's filesystem.
  inlineFiles: InlineFile[];
}

// InlineFile is one in-draft payload file. Same wire shape as
// InlineScript but has its own list so the wrapper-script editor and
// the multi-file editor stay independent.
interface InlineFile {
  name: string;
  content: string; // raw text (UTF-8); base64-encoded at save/submit
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
  inlineFiles: [],
};

// SaveDialogValues is the state held in the save-template dialog as
// the user edits. The dialog is shared between the manual "Save as
// template" button and the agent's save_template chat tool — both
// open it with sensibly-prefilled values, the user can edit any of
// them before confirming.
interface SaveDialogValues {
  id: string;            // slug; empty = server slugifies from name
  name: string;
  description: string;
  visibility: 'private' | 'shared';
}

// SaveDialogResult is what we hand back to the agent once the dialog
// closes. action distinguishes a fresh save from an overwrite (so
// the LLM can phrase its reply correctly) and from a user cancel.
type SaveDialogResult =
  | { ok: true; action: 'saved' | 'overwrote'; id: string; visibility: 'private' | 'shared' }
  | { ok: false; error: string };

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
  // Mirror of `draft` for chat-tool handlers that READ state. The
  // hooks bag is memoized so we don't churn `useChat`'s onToolCall
  // binding on every keystroke; that means handler closures don't
  // see fresh `draft` values. Mutating tools sidestep the issue by
  // using `setDraft((prev) => …)` (the functional updater always
  // sees current state), but read-only tools like read_inline_file
  // must reach for this ref to avoid returning "(none)" right after
  // a successful set_inline_script. Update is a passive side-effect
  // — never write to draftRef during render.
  const draftRef = useRef(draft);
  useEffect(() => {
    draftRef.current = draft;
  }, [draft]);

  // Current user identity. Used to identify which user-source
  // templates are "mine" (and therefore overwritable from the save
  // dialog) vs. "shared by someone else" (read-only — saving creates
  // a new entry under the actor instead of overwriting). Cached for
  // the lifetime of the session — it's a feature flag, not state.
  const meQuery = useQuery({
    queryKey: ['auth-me'],
    queryFn: api.auth.me,
    staleTime: Infinity,
    retry: false,
  });
  const currentUser = meQuery.data?.username ?? '';

  const tplQuery = useQuery({
    queryKey: ['templates'],
    queryFn: api.templates.list,
  });
  const templates = tplQuery.data?.templates ?? [];
  // IDs the actor has personally saved. Used to flag the save dialog
  // as "Overwrite" rather than "Save", and to drive the save_template
  // tool's `action` reply (saved vs overwrote). Computed against the
  // user list because the picker also surfaces shared templates from
  // other owners — those don't count as "mine."
  const ownTemplateIDs = useMemo(
    () =>
      new Set(
        templates
          .filter(
            (t) =>
              t.source === 'user' && (!t.owner || t.owner === currentUser),
          )
          .map((t) => t.id),
      ),
    [templates, currentUser],
  );

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
    // Additional inline files (e.g. analyze.py the wrapper invokes)
    // ship as ordinary 0644 sandbox files. base64-encoded the same
    // way as the wrapper script.
    for (const f of draft.inlineFiles) {
      const trimmedName = f.name.trim();
      if (!trimmedName) continue;
      draftFiles.push({
        name: trimmedName,
        content: utf8ToBase64(f.content),
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
  // the table by hand or pastes a CSV). 'count' submits a flat number
  // of copies of the template (HTCondor's `queue N`); the per-job
  // table is unused. 'upload' is the directory/tarball mode.
  // where the user picks a directory or tarball, and each contained
  // file becomes one row + one per-job input.
  const [tableSource, setTableSource] = useState<TableSource>('manual');
  // count is the per-job count for tableSource === 'count'. Starts at
  // 1 — a single copy is the safest default, especially for the
  // chat-driven path where the LLM may set count without realizing it
  // overrides the manual rows.
  const [count, setCount] = useState<number>(1);
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
  // Per-field override mask: which of cpus/memory/disk/gpus the user
  // wants the form values to override. Each field defaults to "off"
  // when the template already sets that attribute (so we don't
  // silently rewrite what the template author chose) and "on" when
  // the template is silent (so the schedd has something to plan
  // against). The user can flip individual fields freely — overriding
  // only memory while inheriting cpus and disk is fine.
  const templateHasCoreResources = useMemo(
    () => bodyHasCoreResourceRequests(active.contents),
    [active.contents],
  );
  const [overrideFields, setOverrideFields] = useState<ResourceFieldMask>({
    cpus: false,
    memory: false,
    disk: false,
    gpus: false,
  });
  const [resources, setResources] = useState<ResourceRequest>(
    DEFAULT_RESOURCE_REQUEST,
  );

  // --- Chat assistant state -----------------------------------------
  //
  // recentlyChanged tracks the section keys the LLM just mutated so the
  // UI can flash them. Keys: "template" | "table" | "inputs" | "resources"
  // | "submit". Each entry is auto-removed by a timeout (~3s) so the
  // flash is transient.
  const [recentlyChanged, setRecentlyChanged] = useState<Set<string>>(new Set());
  const recentlyChangedTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );
  const flashSection = useCallback((key: string) => {
    setRecentlyChanged((prev) => {
      if (prev.has(key)) return prev;
      const next = new Set(prev);
      next.add(key);
      return next;
    });
    const existing = recentlyChangedTimers.current.get(key);
    if (existing) clearTimeout(existing);
    const t = setTimeout(() => {
      setRecentlyChanged((prev) => {
        if (!prev.has(key)) return prev;
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
      recentlyChangedTimers.current.delete(key);
    }, 3000);
    recentlyChangedTimers.current.set(key, t);
  }, []);

  useEffect(
    () => () => {
      // Clear pending flash timeouts on unmount; storing the Map ref
      // means we don't need to chase down each timer ID individually.
      for (const t of recentlyChangedTimers.current.values()) clearTimeout(t);
      recentlyChangedTimers.current.clear();
    },
    [],
  );

  // When the active template changes, prime resources from whatever
  // it declared (so the form is a faithful starting point if the user
  // *does* choose to override) and reset the per-field override flags
  // based on which attributes the template already covers. A field is
  // ON by default exactly when the template is silent on it — that
  // way we don't accidentally rewrite a template author's deliberate
  // choice, and we don't leave a silent template with no resource
  // numbers at all.
  useEffect(() => {
    // Effect synchronizes form state to the active template — the
    // navigation-reset-style pattern set-state-in-effect is
    // heuristically wrong about. Silenced on the setState calls
    // explicitly, like the other "sync derived state" effects in
    // this file.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setResources(readResourcesFromBody(active.contents));
    setOverrideFields({
      cpus: getAttribute(active.contents, 'request_cpus') === undefined,
      memory: getAttribute(active.contents, 'request_memory') === undefined,
      disk: getAttribute(active.contents, 'request_disk') === undefined,
      // GPUs are opt-in: most jobs don't want them, and a template
      // that's silent on request_gpus shouldn't suddenly start
      // requesting one because the form widget defaults to 0.
      gpus: false,
    });
  }, [active.contents]);

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
      // Per-field override: only the fields whose checkbox is on get
      // rewritten in the body. If none are on, the body is passed
      // through untouched (and we skip the rewrite entirely so we
      // don't risk reordering attribute lines).
      const anyOverride =
        overrideFields.cpus ||
        overrideFields.memory ||
        overrideFields.disk ||
        overrideFields.gpus;
      let effectiveContents = anyOverride
        ? applyResourcesToBody(active.contents, resources, overrideFields)
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
      // toggles and would be stale. `count` mode bypasses the table
      // entirely and submits N copies of the same body.
      let body: string;
      if (tableSource === 'count') {
        body = buildSubmitFileWithCount(effectiveContents, count);
      } else {
        const effectiveRows = tableSource === 'upload' ? uploadRows : rows;
        body = buildSubmitFile(
          effectiveContents,
          active.columns.map((c) => c.name),
          effectiveRows,
        );
      }
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
  // The save flow is dialog-gated: both the manual "Save as template"
  // button and the agent's `save_template` chat tool open the same
  // dialog, the user confirms (possibly editing id/name/description/
  // visibility), then this mutation runs with the dialog's values.
  // Going through one mutation regardless of trigger keeps the
  // post-save invalidation/redirect logic in one place.
  const saveTpl = useMutation({
    mutationFn: (override: {
      id?: string;
      name: string;
      description: string;
      visibility: 'private' | 'shared';
    }) => {
      // Collect the per-template attachment list: explicit user-dropped
      // input files + the inline wrapper script + each additional
      // inline file. base64-encoded so the save endpoint accepts the
      // same envelope the SPA also sends per-job at submit time.
      const files: TemplateInputFile[] = draft.inputFiles.map(
        ({ name, content }) => ({ name, content }),
      );
      if (draft.inlineScript && draft.inlineScript.name.trim() !== '') {
        files.push({
          name: draft.inlineScript.name.trim(),
          content: utf8ToBase64(draft.inlineScript.content),
        });
      }
      for (const f of draft.inlineFiles) {
        const trimmedName = f.name.trim();
        if (!trimmedName) continue;
        files.push({
          name: trimmedName,
          content: utf8ToBase64(f.content),
        });
      }
      return api.templates.save({
        id: override.id,
        name: override.name,
        description: override.description,
        visibility: override.visibility,
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

  // Dialog open state. `pending` carries the agent's resolve callback
  // when the dialog was triggered from a chat tool — onConfirm /
  // onCancel call it to deliver the result back to the LLM. Manual
  // (button-triggered) opens leave pending=null and onConfirm just
  // closes after the mutation resolves.
  const [saveDialog, setSaveDialog] = useState<null | {
    initial: SaveDialogValues;
    pending?: (result: SaveDialogResult) => void;
  }>(null);

  // The "rows" state is per-mode; pick the right one for the
  // disabled check so toggling into upload mode (which clears the
  // user's edits but preserves the manual rows in state) doesn't
  // silently re-enable the button on stale data.
  const effectiveRowsForGate =
    tableSource === 'upload' ? uploadRows : rows;
  // Queue-line guard. The page synthesizes the queue statement from
  // the table rows; any queue line in the body would either duplicate
  // or contradict the synthesized one. Surface this BEFORE the user
  // hits Submit (the schedd would also reject it, but only after a
  // round-trip and a less helpful error).
  const bodyHasQueue = useMemo(
    () => bodyHasQueueLine(active.contents),
    [active.contents],
  );

  // Effective per-job count. In count mode this is the user-set
  // number; otherwise it's just the row count that will be submitted.
  // Used for the button label and the row-count-based gates.
  const effectiveJobCount =
    tableSource === 'count'
      ? Math.max(1, Math.floor(count) || 1)
      : effectiveRowsForGate.length;

  // submitBlockedReason returns null when the form is ready to submit
  // OR a structured reason describing what's wrong + which section
  // the user (or chat-driven highlight) should look at. We surface
  // this prose on the page so a greyed-out button is never a mystery.
  // Order matters: report the FIRST blocker so the user fixes one
  // thing at a time instead of reading a wall of red.
  const submitBlockedReason = useMemo<
    { message: string; section: 'template' | 'table' | 'inputs' | 'resources' | 'submit' } | null
  >(() => {
    if (!active.contents.trim()) {
      return {
        section: 'template',
        message: 'The submit-file body is empty. Pick a template or fill in the body.',
      };
    }
    if (bodyHasQueue) {
      return {
        section: 'template',
        message:
          'The submit-file body contains a "queue" line. The page synthesizes the queue statement from the table; remove the line.',
      };
    }
    if (tableSource === 'count') {
      if (!Number.isFinite(count) || count < 1) {
        return { section: 'table', message: 'Job count must be at least 1.' };
      }
      if (count > MAX_TABLE_COUNT) {
        return {
          section: 'table',
          message: `Job count ${count} exceeds the per-batch limit of ${MAX_TABLE_COUNT}.`,
        };
      }
    } else {
      if (effectiveRowsForGate.length === 0) {
        return {
          section: 'table',
          message:
            tableSource === 'upload'
              ? 'No files picked yet. Drop a directory or tarball to populate the table, switch to manual mode, or pick "Run N copies".'
              : 'The job table has no rows. Add a row, paste CSV, switch to upload mode, or pick "Run N copies".',
        };
      }
      if (effectiveRowsForGate.some((r) => r.every((c) => c.trim() === ''))) {
        return {
          section: 'table',
          message: 'One of the table rows is completely empty; either fill it in or remove it.',
        };
      }
    }
    return null;
  }, [
    active.contents,
    bodyHasQueue,
    count,
    effectiveRowsForGate,
    tableSource,
  ]);
  const submitDisabled = submit.isPending || submitBlockedReason !== null;

  // Chat surface gating. Same /api/v1/chat/info probe the jobs page
  // uses; the server returns enabled=false when the LLM key isn't
  // configured or MCP is off. Submit page has no "have any jobs"
  // requirement (the user is creating jobs, not inspecting them).
  const { data: chatInfo } = useQuery({
    queryKey: ['chat-info'],
    queryFn: api.chat.info,
    staleTime: Infinity,
    retry: false,
  });
  const chatVisible = !!chatInfo?.enabled;

  // Client-side tool dispatchers, keyed by the names the server
  // advertises for page="submit". The hooks mutate page state via the
  // existing setters, then call flashSection to surface the change in
  // the UI. Server-side tools (query_slots, doc_search, etc.) don't
  // need entries here — they execute on the server and the result
  // arrives as a tool_result the panel renders inline.
  //
  // === KEEP IN SYNC WITH submitPageInstructions IN
  // httpserver/handlers_chat_tools.go ===
  // The server-side prose tells the LLM what these tools do; if you
  // add or remove a hook here, update the matching description so
  // the model doesn't hallucinate (or miss) tools.
  const chatHooks = useMemo<Record<string, ToolHandler>>(
    () => ({
      highlight_section: (input) => {
        const sec = String(input.section ?? '');
        if (!['template', 'table', 'inputs', 'resources', 'submit'].includes(sec)) {
          return { ok: false, error: `unknown section: ${sec}` };
        }
        flashSection(sec);
        return { ok: true, highlighted: sec };
      },
      set_template_body: (input) => {
        const contents = String(input.contents ?? '');
        if (!contents.trim()) {
          return { ok: false, error: 'contents must be non-empty' };
        }
        // Reject bodies that include a queue line. The page synthesizes
        // `queue <cols> from ((...))` from the table rows and a
        // hand-written queue would either duplicate that line (HTCondor
        // submit error) or produce a job count that doesn't match the
        // user's table. Rejecting here surfaces the problem to the LLM
        // immediately so it can retry without the offending line; the
        // error text below also makes it past the SDK back into the
        // assistant's next turn.
        if (bodyHasQueueLine(contents)) {
          return {
            ok: false,
            error:
              'submit-file body must not contain a "queue" line; the page synthesizes one from the table rows. Remove the queue line and resend.',
          };
        }
        // Ensure we're in custom mode — we shouldn't mutate a library
        // template under the user's nose. If they're in library mode,
        // fork the current selection into a draft first so they don't
        // lose their starting point.
        if (mode !== 'custom') {
          setDraft((prev) => ({
            ...prev,
            name: selected?.name ? `${selected.name} (edited)` : prev.name,
            description: selected?.description ?? prev.description,
            columns: selected?.columns ?? prev.columns,
            contents,
          }));
          setMode('custom');
        } else {
          setDraft((prev) => ({ ...prev, contents }));
        }
        flashSection('template');
        return { ok: true, length: contents.length };
      },
      set_inline_script: (input) => {
        const filename = String(input.filename ?? '').trim();
        const content = String(input.content ?? '');
        if (!filename || !content) {
          return { ok: false, error: 'filename and content are both required' };
        }
        if (mode !== 'custom') {
          // Same fork-into-draft semantics as set_template_body.
          setDraft((prev) => ({
            ...prev,
            name: selected?.name ? `${selected.name} (edited)` : prev.name,
            description: selected?.description ?? prev.description,
            columns: selected?.columns ?? prev.columns,
            contents: selected?.contents ?? prev.contents,
            inlineScript: { name: filename, content },
          }));
          setMode('custom');
        } else {
          setDraft((prev) => ({
            ...prev,
            inlineScript: { name: filename, content },
          }));
        }
        flashSection('template');
        return { ok: true, filename, length: content.length };
      },
      clear_inline_script: () => {
        setDraft((prev) =>
          prev.inlineScript === null ? prev : { ...prev, inlineScript: null },
        );
        flashSection('template');
        return { ok: true };
      },

      // Multi-file inline editing. The wrapper script is still
      // managed via set_inline_script / clear_inline_script (the
      // agent has different mental model for "the executable" vs
      // "an additional payload file"); these tools refuse to touch
      // the wrapper script's filename to keep the boundary clean.
      add_inline_file: (input) => {
        const name = String(input.name ?? '').trim();
        const content = String(input.content ?? '');
        if (!name) {
          return { ok: false, error: 'name is required' };
        }
        if (name.includes('/')) {
          return {
            ok: false,
            error: 'name must not contain path separators',
          };
        }
        let conflict: string | null = null;
        setDraft((prev) => {
          if (prev.inlineScript && prev.inlineScript.name.trim() === name) {
            conflict = 'wrapper-script';
            return prev;
          }
          if (prev.inlineFiles.some((f) => f.name === name)) {
            conflict = 'inline-file';
            return prev;
          }
          if (prev.inputFiles.some((f) => f.name === name)) {
            conflict = 'input-file';
            return prev;
          }
          return {
            ...prev,
            inlineFiles: [...prev.inlineFiles, { name, content }],
          };
        });
        if (conflict === 'wrapper-script') {
          return {
            ok: false,
            error: `"${name}" is the wrapper script; use set_inline_script or pick a different name`,
          };
        }
        if (conflict === 'inline-file') {
          return {
            ok: false,
            error: `inline file "${name}" already exists; use set_inline_file_content to overwrite or replace_in_inline_file to edit`,
          };
        }
        if (conflict === 'input-file') {
          return {
            ok: false,
            error: `"${name}" is already in the user-uploaded input files; pick a different name`,
          };
        }
        flashSection('template');
        return { ok: true, name, length: content.length };
      },

      read_inline_file: (input) => {
        const name = String(input.name ?? '').trim();
        if (!name) {
          return { ok: false, error: 'name is required' };
        }
        // Read via the ref (NOT the closure-captured `draft`) so a
        // tool call immediately after add_inline_file / set_inline_
        // script sees the latest state. The chatHooks memo doesn't
        // depend on `draft` (would churn on every keystroke), so the
        // closure here is stuck at the initial STARTER_DRAFT.
        const d = draftRef.current;
        // Per-tool byte cap. Engine-level truncation would catch a
        // huge content anyway, but a "file too big" error is a
        // better signal to the LLM than silently mid-line-truncated
        // bytes that look like the real file.
        const FILE_BYTE_CAP = 24 * 1024;
        const capped = (kind: 'wrapper-script' | 'inline-file', content: string) => {
          if (content.length > FILE_BYTE_CAP) {
            return {
              ok: false,
              error: `inline file "${name}" exceeds ${FILE_BYTE_CAP} bytes; ask the user about its contents or focus on a specific section.`,
              name,
              kind,
              size_bytes: content.length,
            };
          }
          return { ok: true, name, kind, content };
        };
        if (d.inlineScript && d.inlineScript.name.trim() === name) {
          return capped('wrapper-script', d.inlineScript.content);
        }
        const f = d.inlineFiles.find((x) => x.name === name);
        if (!f) {
          return {
            ok: false,
            error: `inline file "${name}" not found; current files: ${listAllInlineNames(d).join(', ') || '(none)'}`,
          };
        }
        return capped('inline-file', f.content);
      },

      replace_in_inline_file: (input) => {
        const name = String(input.name ?? '').trim();
        const find = String(input.find ?? '');
        const replace = String(input.replace ?? '');
        if (!name) return { ok: false, error: 'name is required' };
        if (find === '') {
          return { ok: false, error: 'find string must not be empty' };
        }
        let result: { ok: boolean; error?: string; matches?: number } = {
          ok: false,
          error: 'unhandled',
        };
        const swap = (text: string): string | null => {
          const occurrences = countOccurrences(text, find);
          if (occurrences === 0) {
            result = {
              ok: false,
              error: `find string not found in "${name}"`,
            };
            return null;
          }
          if (occurrences > 1) {
            result = {
              ok: false,
              error: `find string matches ${occurrences} places in "${name}"; pass more surrounding context to disambiguate`,
              matches: occurrences,
            };
            return null;
          }
          result = { ok: true, matches: 1 };
          return text.replace(find, replace);
        };

        let touched = false;
        setDraft((prev) => {
          if (prev.inlineScript && prev.inlineScript.name.trim() === name) {
            const next = swap(prev.inlineScript.content);
            if (next === null) return prev;
            touched = true;
            return {
              ...prev,
              inlineScript: { ...prev.inlineScript, content: next },
            };
          }
          const idx = prev.inlineFiles.findIndex((f) => f.name === name);
          if (idx < 0) {
            result = {
              ok: false,
              error: `inline file "${name}" not found; current files: ${listAllInlineNames(prev).join(', ') || '(none)'}`,
            };
            return prev;
          }
          const next = swap(prev.inlineFiles[idx].content);
          if (next === null) return prev;
          touched = true;
          const newFiles = [...prev.inlineFiles];
          newFiles[idx] = { ...newFiles[idx], content: next };
          return { ...prev, inlineFiles: newFiles };
        });
        if (touched) flashSection('template');
        return result;
      },

      set_inline_file_content: (input) => {
        const name = String(input.name ?? '').trim();
        const content = String(input.content ?? '');
        if (!name) return { ok: false, error: 'name is required' };
        let action: 'created' | 'overwrote' = 'created';
        let conflict: string | null = null;
        setDraft((prev) => {
          if (prev.inlineScript && prev.inlineScript.name.trim() === name) {
            conflict = 'wrapper-script';
            return prev;
          }
          if (prev.inputFiles.some((f) => f.name === name)) {
            conflict = 'input-file';
            return prev;
          }
          const idx = prev.inlineFiles.findIndex((f) => f.name === name);
          if (idx >= 0) {
            action = 'overwrote';
            const newFiles = [...prev.inlineFiles];
            newFiles[idx] = { ...newFiles[idx], content };
            return { ...prev, inlineFiles: newFiles };
          }
          return {
            ...prev,
            inlineFiles: [...prev.inlineFiles, { name, content }],
          };
        });
        if (conflict === 'wrapper-script') {
          return {
            ok: false,
            error: `"${name}" is the wrapper script; use set_inline_script (and the matching schema) instead`,
          };
        }
        if (conflict === 'input-file') {
          return {
            ok: false,
            error: `"${name}" collides with a user-uploaded input file; rename`,
          };
        }
        flashSection('template');
        return { ok: true, name, action, length: content.length };
      },

      delete_inline_file: (input) => {
        const name = String(input.name ?? '').trim();
        if (!name) return { ok: false, error: 'name is required' };
        let removed = false;
        setDraft((prev) => {
          if (!prev.inlineFiles.some((f) => f.name === name)) {
            return prev;
          }
          removed = true;
          return {
            ...prev,
            inlineFiles: prev.inlineFiles.filter((f) => f.name !== name),
          };
        });
        if (removed) flashSection('template');
        return { ok: true, name, removed };
      },

      // Open the save-template dialog with the agent's suggested
      // values pre-filled. Returns a Promise that resolves once the
      // user clicks Save / Overwrite / Cancel — that's why this hook
      // is async (the SDK awaits the return value to populate the
      // tool result).
      save_template: (input) => {
        // Same staleness reasoning as read_inline_file: chatHooks
        // doesn't depend on `draft` (would churn on every keystroke),
        // so fall back to the latest values via draftRef rather than
        // the closure-captured one.
        const d = draftRef.current;
        const id = slugify(String(input.id ?? '') || d.name);
        const name = String(input.name ?? '').trim() || d.name;
        const description =
          String(input.description ?? '').trim() || d.description;
        const visibility =
          input.visibility === 'shared' ? 'shared' : 'private';
        if (!name) {
          return {
            ok: false,
            error:
              'no name to save under; ask the user for a template name first or call set_template_description',
          };
        }
        return new Promise<SaveDialogResult>((resolve) => {
          setSaveDialog({
            initial: { id, name, description, visibility },
            pending: resolve,
          });
        });
      },
      set_resources: (input) => {
        // The chat tool schema uses snake_case (memory_mb / disk_mb)
        // because that's the convention HTCondor uses for ClassAd
        // attributes — keeps the LLM's mental model consistent. The
        // ResourceRequest type is camelCase, so we translate at this
        // boundary.
        const next: Partial<ResourceRequest> = {};
        if (typeof input.cpus === 'number') next.cpus = input.cpus;
        if (typeof input.memory_mb === 'number') next.memoryMB = input.memory_mb;
        if (typeof input.disk_mb === 'number') next.diskMB = input.disk_mb;
        if (Object.keys(next).length === 0) {
          return { ok: false, error: 'at least one of cpus/memory_mb/disk_mb required' };
        }
        setResources((prev) => ({ ...prev, ...next }));
        // Turn on the override flag for whichever fields the chat
        // actually touched. Same per-field semantics the user gets
        // from the checkboxes — overriding only memory leaves cpus
        // and disk inheriting from the template.
        setOverrideFields((prev) => ({
          ...prev,
          cpus: prev.cpus || next.cpus !== undefined,
          memory: prev.memory || next.memoryMB !== undefined,
          disk: prev.disk || next.diskMB !== undefined,
        }));
        flashSection('resources');
        return { ok: true, applied: next };
      },
      add_template_input_file: (input) => {
        const name = String(input.name ?? '').trim();
        const content = String(input.content ?? '');
        if (!name) return { ok: false, error: 'name is required' };
        // The submit page already accepts arbitrary text files in
        // draft.inputFiles. We base64-encode here so the existing
        // save/submit pipeline can ship the bytes verbatim.
        const encoded = utf8ToBase64(content);
        setDraft((prev) => ({
          ...prev,
          inputFiles: [
            ...prev.inputFiles.filter((f) => f.name !== name),
            {
              id: crypto.randomUUID(),
              name,
              content: encoded,
              size: new Blob([content]).size,
            },
          ],
        }));
        if (mode !== 'custom') setMode('custom');
        flashSection('template');
        return { ok: true, name, bytes: content.length };
      },
      select_template: (input) => {
        const id = String(input.id ?? '').trim();
        if (!id) return { ok: false, error: 'id is required' };
        const match = templates.find((t) => t.id === id);
        if (!match) {
          return {
            ok: false,
            error: `no template with id ${JSON.stringify(id)}; call list_submit_templates to see available ids`,
          };
        }
        setMode('library');
        setSelectedID(id);
        flashSection('template');
        return { ok: true, id, name: match.name };
      },
      switch_to_custom_template: (input) => {
        const startFrom = String(input.start_from ?? 'current');
        if (startFrom === 'blank') {
          setDraft(STARTER_DRAFT);
        } else if (selected) {
          setDraft({
            name: `${selected.name} (edited)`,
            description: selected.description ?? '',
            columns: selected.columns,
            contents: selected.contents,
            inputFiles: [],
            inlineScript: null,
            inlineFiles: [],
          });
        }
        setMode('custom');
        flashSection('template');
        return { ok: true, mode: 'custom', start_from: startFrom };
      },
      set_template_description: (input) => {
        const name = typeof input.name === 'string' ? input.name : undefined;
        const description =
          typeof input.description === 'string' ? input.description : undefined;
        if (name === undefined && description === undefined) {
          return { ok: false, error: 'pass name or description (or both)' };
        }
        setDraft((prev) => ({
          ...prev,
          ...(name !== undefined ? { name } : {}),
          ...(description !== undefined ? { description } : {}),
        }));
        if (mode !== 'custom') setMode('custom');
        flashSection('template');
        return { ok: true };
      },
      set_template_columns: (input) => {
        const raw = input.columns;
        if (!Array.isArray(raw)) {
          return { ok: false, error: 'columns must be an array of {name, description?}' };
        }
        // Validate up-front so the LLM gets a precise error rather than
        // a partial mutation. Names must be HTCondor identifiers: same
        // rule the queue-statement builder enforces at submit time.
        const cleaned: TemplateColumn[] = [];
        for (let i = 0; i < raw.length; i++) {
          const c = raw[i] as Record<string, unknown> | null;
          if (!c || typeof c !== 'object') {
            return { ok: false, error: `columns[${i}] must be an object with a name` };
          }
          const name = typeof c.name === 'string' ? c.name : '';
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
            return {
              ok: false,
              error: `columns[${i}].name "${name}" is not a valid identifier; use letters, digits, underscores; must not start with a digit`,
            };
          }
          const description = typeof c.description === 'string' ? c.description : undefined;
          cleaned.push({ name, ...(description ? { description } : {}) });
        }
        setDraft((prev) => ({ ...prev, columns: cleaned }));
        if (mode !== 'custom') setMode('custom');
        flashSection('template');
        return { ok: true, columns: cleaned.length };
      },
      set_table_rows: (input) => {
        const raw = input.rows;
        if (!Array.isArray(raw)) {
          return { ok: false, error: 'rows must be an array of arrays of strings' };
        }
        const expected = active.columns.length;
        // Coerce each cell to a string and pad/truncate to the column
        // count. This mirrors what the manual editor does when columns
        // are added/removed: the row reshape doesn't drop user data
        // silently, but extra cells the LLM tacked on past the schema
        // get trimmed.
        const rows: string[][] = raw.map((row) => {
          const out: string[] = [];
          if (Array.isArray(row)) {
            for (let i = 0; i < expected; i++) {
              out.push(typeof row[i] === 'string' ? (row[i] as string) : String(row[i] ?? ''));
            }
          } else {
            for (let i = 0; i < expected; i++) out.push('');
          }
          return out;
        });
        setRows(rows);
        // Switch out of upload mode — the LLM-supplied rows override
        // any prior file selection. The user can flip back to upload
        // mode by hand if they didn't want this.
        setTableSource('manual');
        flashSection('table');
        return { ok: true, rows: rows.length, columns: expected };
      },
      set_table_count: (input) => {
        const n = Number(input.count);
        if (!Number.isFinite(n) || n < 1) {
          return { ok: false, error: 'count must be a positive integer' };
        }
        if (n > MAX_TABLE_COUNT) {
          return {
            ok: false,
            error: `count ${n} exceeds the per-batch limit of ${MAX_TABLE_COUNT}`,
          };
        }
        setCount(Math.floor(n));
        setTableSource('count');
        flashSection('table');
        return { ok: true, count: Math.floor(n) };
      },
    }),
    [active.columns.length, flashSection, mode, selected, templates],
  );

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Submit a Batch</h1>
        <p className="text-sm text-gray-500">
          Pick or write a template, fill the table with one row per job,
          attach any input files, then submit.
        </p>
      </div>

      {/*
        Assistant lives at the top of the page (vs. the bottom on the
        jobs page) and is open by default — the agent is the primary
        affordance here for first-time submitters who'd rather describe
        their job in prose than wrestle with the form. The form below
        stays the source of truth; the assistant just edits it.
      */}
      <ChatPanel
        visible={chatVisible}
        page="submit"
        hooks={chatHooks}
        // Submit page has no destructive server-side tools advertised;
        // hide the auto-approve checkbox row entirely.
        confirmableTools={[]}
        headerLabel="Submit assistant"
        togglerLabel="Ask the submit assistant"
        pageHelp={`Try "scaffold a job that runs my Python script", "what GPU types are available?", or "wrap my command with a setup script".`}
        defaultOpen
      />

      <ChatHighlight active={recentlyChanged.has('template')}>
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
          onSave={() =>
            // Manual button → open the same dialog the agent uses.
            // Pre-fill from the current draft so the user mostly just
            // confirms; they can still rename or flip visibility
            // before saving.
            setSaveDialog({
              initial: {
                id: slugify(draft.name),
                name: draft.name,
                description: draft.description,
                visibility: 'private',
              },
            })
          }
          saveState={saveTpl}
          currentUser={currentUser}
        />
      </ChatHighlight>

      <ChatHighlight active={recentlyChanged.has('table')}>
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
          count={count}
          setCount={setCount}
        />
      </ChatHighlight>

      {libraryUploadWarning && (
        <div
          role="alert"
          className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          ⚠ {libraryUploadWarning}
        </div>
      )}

      {bodyHasQueue && (
        <div
          role="alert"
          className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          ⚠ The submit-file body contains a <code>queue</code> line. The
          page synthesizes the queue statement from the table rows;
          remove the <code>queue</code> line from the body to enable
          submit.
        </div>
      )}

      <ChatHighlight active={recentlyChanged.has('inputs')}>
        <InputsSection files={files} setFiles={setFiles} disabled={submit.isPending} />
      </ChatHighlight>

      <ChatHighlight active={recentlyChanged.has('resources')}>
        <ResourcesSection
          templateContents={active.contents}
          fields={overrideFields}
          setFields={setOverrideFields}
          resources={resources}
          setResources={setResources}
        />
      </ChatHighlight>

      {submit.isError && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {submit.error instanceof ApiError
            ? `${submit.error.status}: ${submit.error.message}`
            : (submit.error as Error).message}
        </div>
      )}

      <ChatHighlight active={recentlyChanged.has('submit')}>
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <button
              onClick={() => submit.mutate()}
              disabled={submitDisabled}
              className="rounded bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
            >
              {submit.isPending
                ? 'Submitting…'
                : `Submit batch (${effectiveJobCount} job${effectiveJobCount === 1 ? '' : 's'})`}
            </button>
            <span className="text-xs text-gray-500">
              Submitting as <code>{active.name}</code>.
            </span>
          </div>
          {/*
            Surface WHY the button is disabled. A greyed-out button is
            otherwise a guessing game; the user is left wondering which
            section to fix. We tell them in prose AND drop a button
            that flashes the offending section so they can find it on
            a long page.
          */}
          {submitBlockedReason && !submit.isPending && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900"
            >
              <span className="font-semibold">Can't submit yet:</span>
              <span className="flex-1">{submitBlockedReason.message}</span>
              <button
                type="button"
                onClick={() => flashSection(submitBlockedReason.section)}
                className="rounded border border-amber-400 bg-white px-2 py-0.5 text-amber-800 hover:bg-amber-100"
              >
                Show me
              </button>
            </div>
          )}
        </div>
      </ChatHighlight>

      {saveDialog && (
        <SaveTemplateDialog
          initial={saveDialog.initial}
          existingIDs={ownTemplateIDs}
          isPending={saveTpl.isPending}
          error={
            saveTpl.error
              ? saveTpl.error instanceof Error
                ? saveTpl.error.message
                : String(saveTpl.error)
              : null
          }
          onConfirm={async (values) => {
            try {
              await saveTpl.mutateAsync({
                id: values.id || undefined,
                name: values.name,
                description: values.description,
                visibility: values.visibility,
              });
              const action: 'saved' | 'overwrote' =
                ownTemplateIDs.has(values.id) ? 'overwrote' : 'saved';
              saveDialog.pending?.({
                ok: true,
                action,
                id: values.id,
                visibility: values.visibility,
              });
              setSaveDialog(null);
            } catch (e) {
              // Surface the error in-dialog (saveTpl.error already
              // populated by useMutation) and DO NOT close — let the
              // user fix and retry. The agent's promise stays
              // unresolved until the user either succeeds or cancels.
              void e;
            }
          }}
          onCancel={() => {
            saveDialog.pending?.({
              ok: false,
              error: 'user canceled the save dialog',
            });
            saveTpl.reset();
            setSaveDialog(null);
          }}
        />
      )}
    </div>
  );
}

// SaveTemplateDialog is the confirmation gate for both the manual
// "Save as template" button and the agent's save_template chat tool.
// Pre-fills with sensibly-suggested values (id slug, name,
// description, visibility); the user is free to change any of them
// before clicking Save (or Overwrite if the id matches one they've
// previously saved). Visibility offers Private / Shared with a
// short explanation so users don't accidentally publish.
function SaveTemplateDialog({
  initial,
  existingIDs,
  isPending,
  error,
  onConfirm,
  onCancel,
}: {
  initial: SaveDialogValues;
  existingIDs: Set<string>;
  isPending: boolean;
  error: string | null;
  onConfirm: (values: SaveDialogValues) => void;
  onCancel: () => void;
}) {
  const [values, setValues] = useState<SaveDialogValues>(initial);
  // Re-seed from initial when the dialog reopens with different
  // suggestions (e.g. agent invokes with a new name after the user
  // canceled the previous attempt).
  useEffect(() => {
    setValues(initial);
  }, [initial]);

  const idTrimmed = values.id.trim();
  const isOverwrite = idTrimmed !== '' && existingIDs.has(idTrimmed);
  const idValid =
    idTrimmed === '' || /^[a-z0-9][a-z0-9-]*[a-z0-9]?$/.test(idTrimmed);
  const submittable =
    !isPending && values.name.trim() !== '' && idValid;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div
        role="dialog"
        aria-labelledby="save-template-dialog-title"
        aria-modal="true"
        className="w-full max-w-lg rounded bg-white p-5 shadow-lg"
      >
        <h2
          id="save-template-dialog-title"
          className="text-lg font-semibold text-gray-900"
        >
          {isOverwrite ? 'Overwrite template' : 'Save as template'}
        </h2>
        <p className="mt-1 text-xs text-gray-500">
          {isOverwrite
            ? `An existing template with id "${idTrimmed}" will be replaced.`
            : 'Saves the current submit-file body, columns, and inline files as a reusable template.'}
        </p>

        <div className="mt-4 space-y-3 text-sm">
          <label className="block">
            <div className="text-xs font-medium uppercase tracking-wide text-gray-500">
              Name
            </div>
            <input
              type="text"
              value={values.name}
              onChange={(e) => {
                const name = e.target.value;
                setValues((v) => ({
                  ...v,
                  name,
                  // Re-slugify the id whenever the user is still
                  // working with the suggested slug (we infer this
                  // by comparing against a slugify of the previous
                  // name). Once the user has hand-edited the id
                  // they take ownership of it and we stop touching.
                  id:
                    v.id === slugify(initial.name) ||
                    v.id === '' ||
                    v.id === slugify(v.name)
                      ? slugify(name)
                      : v.id,
                }));
              }}
              className="mt-0.5 w-full rounded border border-gray-300 px-2 py-1"
              autoFocus
            />
          </label>
          <label className="block">
            <div className="text-xs font-medium uppercase tracking-wide text-gray-500">
              ID (slug)
            </div>
            <input
              type="text"
              value={values.id}
              onChange={(e) =>
                setValues((v) => ({ ...v, id: e.target.value }))
              }
              placeholder="auto-derived from name if empty"
              className={`mt-0.5 w-full rounded border px-2 py-1 font-mono text-xs ${
                idValid ? 'border-gray-300' : 'border-red-400'
              }`}
            />
            {!idValid && (
              <p className="mt-0.5 text-[11px] text-red-700">
                ID must be lowercase alphanumeric with hyphens (e.g.
                gpu-analyze).
              </p>
            )}
          </label>
          <label className="block">
            <div className="text-xs font-medium uppercase tracking-wide text-gray-500">
              Description
            </div>
            <textarea
              value={values.description}
              onChange={(e) =>
                setValues((v) => ({ ...v, description: e.target.value }))
              }
              rows={2}
              className="mt-0.5 w-full resize-none rounded border border-gray-300 px-2 py-1"
            />
          </label>
          <fieldset className="rounded border border-gray-200 px-3 py-2">
            <legend className="px-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Visibility
            </legend>
            <label className="flex items-start gap-2 py-1">
              <input
                type="radio"
                name="visibility"
                checked={values.visibility === 'private'}
                onChange={() =>
                  setValues((v) => ({ ...v, visibility: 'private' }))
                }
                className="mt-0.5"
              />
              <span>
                <span className="font-medium">Private</span>
                <span className="ml-1 text-xs text-gray-500">
                  — only you see it.
                </span>
              </span>
            </label>
            <label className="flex items-start gap-2 py-1">
              <input
                type="radio"
                name="visibility"
                checked={values.visibility === 'shared'}
                onChange={() =>
                  setValues((v) => ({ ...v, visibility: 'shared' }))
                }
                className="mt-0.5"
              />
              <span>
                <span className="font-medium">Shared</span>
                <span className="ml-1 text-xs text-gray-500">
                  — every authenticated user can see it in their
                  picker. Only you can edit or delete.
                </span>
              </span>
            </label>
          </fieldset>
        </div>

        {error && (
          <div className="mt-3 rounded border border-red-200 bg-red-50 p-2 text-xs text-red-700">
            {error}
          </div>
        )}

        <div className="mt-5 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm(values)}
            disabled={!submittable}
            className={`rounded px-3 py-1.5 text-sm font-medium text-white ${
              isOverwrite
                ? 'bg-amber-600 hover:bg-amber-700'
                : 'bg-brand-600 hover:bg-brand-700'
            } disabled:opacity-50`}
          >
            {isPending ? 'Saving…' : isOverwrite ? 'Overwrite' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ChatHighlight wraps a child block with a transient yellow ring +
// soft-pulse animation when `active` is true. The agent's tool
// callbacks call flashSection(key) which flips the matching `active`
// for ~3 seconds before clearing. Wrapping (vs threading className
// down) lets us keep the section components ignorant of the chat
// layer.
function ChatHighlight({
  active,
  children,
}: {
  active: boolean;
  children: React.ReactNode;
}) {
  // The ring/pulse is purely Tailwind so we avoid pulling in a custom
  // keyframe; the existing `animate-pulse` is enough of a visual cue
  // and matches what the jobs page uses for highlight_job.
  const cls = active
    ? 'ring-2 ring-amber-300 ring-offset-2 rounded-lg animate-pulse transition-shadow'
    : 'transition-shadow';
  return <div className={cls}>{children}</div>;
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
  currentUser,
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
  currentUser: string;
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
                <TemplateCombobox
                  templates={templates}
                  selectedID={selectedID}
                  setSelectedID={setSelectedID}
                  currentUser={currentUser}
                />
              </label>
              {selected && (
                <div className="rounded border border-gray-200 bg-gray-50 p-3 text-xs space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-700">{selected.name}</span>
                    <SourceBadge source={selected.source} />
                    {selected.owner && selected.owner !== currentUser && (
                      <span className="text-gray-500">by {selected.owner}</span>
                    )}
                  </div>
                  {selected.owner && selected.owner !== currentUser && (
                    // Shared-template warning: when user A loads user B's
                    // shared template, A is about to submit a job using
                    // submit-file content B authored. The job runs as A,
                    // so anything B encoded (executable, transfer files,
                    // arguments, accounting groups) executes with A's
                    // identity. This banner is the "review carefully"
                    // affordance the security audit asked for: makes
                    // shared-by-others templates visually distinct from
                    // user-A's own and from system-built-in templates.
                    <div className="rounded border border-amber-300 bg-amber-50 p-2 text-amber-800">
                      <strong>Authored by {selected.owner}.</strong> Review
                      the template body and any default input files
                      below before submitting — the job will run under
                      your identity, with the schedd attributing every
                      action to you.
                    </div>
                  )}
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
          currentUser={currentUser}
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
  currentUser,
}: {
  draft: CustomDraft;
  setDraft: (d: CustomDraft) => void;
  onSave: () => void;
  saveState: { isPending: boolean; error: unknown };
  templates: Template[];
  currentUser: string;
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
      // Same reasoning as inlineScript: don't auto-promote arbitrary
      // input_files into the multi-file editor on clone. The user
      // can re-add via the chat tool if they want them surfaced.
      inlineFiles: [],
    });
  };

  return (
    <div className="space-y-3 mt-3">
      {/* Clone-from-existing — appears at the top so it's the first
          thing users see when they switch to "Write new template". */}
      {templates.length > 0 && (
        <CloneFromPicker
          templates={templates}
          onClone={cloneFrom}
          currentUser={currentUser}
        />
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

      <InlineFilesEditor
        files={draft.inlineFiles}
        setFiles={(fs) => setDraft({ ...draft, inlineFiles: fs })}
        reservedNames={inlineFilesReservedNames(draft)}
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

// CloneFromPicker is a one-shot picker that fires cloneFrom on each
// selection and never sticks the value — so the user can clone twice
// in a row without a manual reset. Reuses TemplateCombobox in
// "placeholder + selectedID=''" mode for visual consistency with the
// main library picker (filterable, owner-aware, keyboard-navigable).
function CloneFromPicker({
  templates,
  onClone,
  currentUser,
}: {
  templates: Template[];
  onClone: (id: string) => void;
  currentUser: string;
}) {
  return (
    <div className="rounded border border-dashed border-gray-300 bg-gray-50 px-3 py-2 text-xs">
      <div className="text-gray-600 mb-1">Start from a copy of:</div>
      <TemplateCombobox
        templates={templates}
        selectedID=""
        setSelectedID={onClone}
        placeholder="(pick a template to clone…)"
        currentUser={currentUser}
      />
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

// inlineFilesReservedNames returns the names already taken by the
// wrapper script and user-uploaded input files. The InlineFilesEditor
// surfaces these as conflicts so a user can't accidentally land two
// files with the same name in the job sandbox (which would cause one
// to clobber the other on transfer).
function inlineFilesReservedNames(d: CustomDraft): Set<string> {
  const out = new Set<string>();
  if (d.inlineScript && d.inlineScript.name.trim() !== '') {
    out.add(d.inlineScript.name.trim());
  }
  for (const f of d.inputFiles) out.add(f.name);
  return out;
}

// InlineFilesEditor manages the additional in-draft files that ride
// along with the job (the analyze.py / model.R / query.sql etc. that
// the wrapper script invokes). Same backing state the chat tools
// (add_inline_file, replace_in_inline_file, …) mutate, so a user
// editing here and the agent editing through chat see the same list.
//
// Layout: a header with "+ Add file", then one row per file with a
// filename input + content textarea + delete button. Empty list shows
// a one-line nudge so the affordance is discoverable.
function InlineFilesEditor({
  files,
  setFiles,
  reservedNames,
}: {
  files: InlineFile[];
  setFiles: (fs: InlineFile[]) => void;
  reservedNames: Set<string>;
}) {
  const addBlank = () => {
    // Pick a non-conflicting default name (script.py, script-2.py,
    // …). Users can rename freely; the only constraint is uniqueness
    // within the sandbox.
    const taken = new Set([...reservedNames, ...files.map((f) => f.name)]);
    let name = 'script.py';
    let i = 2;
    while (taken.has(name)) {
      name = `script-${i}.py`;
      i++;
    }
    setFiles([...files, { name, content: '' }]);
  };

  const updateAt = (idx: number, patch: Partial<InlineFile>) => {
    const next = [...files];
    next[idx] = { ...next[idx], ...patch };
    setFiles(next);
  };

  const removeAt = (idx: number) => {
    setFiles(files.filter((_, i) => i !== idx));
  };

  return (
    <div className="rounded border border-gray-200 bg-gray-50 p-3 space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <h3 className="text-sm font-medium text-gray-700">
            Inline payload files
          </h3>
          <p className="text-xs text-gray-500">
            Additional files edited inline alongside the wrapper script
            — e.g. <code>analyze.py</code> that <code>run.sh</code>{' '}
            invokes. Uploaded as 0644 in the job&apos;s sandbox (the
            wrapper is the executable). Edit here, or ask the chat
            assistant to scaffold one.
          </p>
        </div>
        <button
          type="button"
          onClick={addBlank}
          className="shrink-0 rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-100"
        >
          + Add file
        </button>
      </div>

      {files.length === 0 ? (
        <p className="text-xs italic text-gray-500">
          No inline files yet. Click &ldquo;+ Add file&rdquo; or ask the
          assistant to create one.
        </p>
      ) : (
        files.map((f, i) => {
          const trimmedName = f.name.trim();
          const dupeWithReserved = reservedNames.has(trimmedName);
          const dupeWithOther = files.some(
            (g, j) => j !== i && g.name.trim() === trimmedName,
          );
          const nameInvalid =
            trimmedName === '' ||
            trimmedName.includes('/') ||
            dupeWithReserved ||
            dupeWithOther;
          const errMsg = !trimmedName
            ? 'name is required'
            : trimmedName.includes('/')
              ? 'name must not contain "/"'
              : dupeWithReserved
                ? 'name conflicts with the wrapper script or an uploaded file'
                : dupeWithOther
                  ? 'name conflicts with another inline file'
                  : null;
          return (
            <div
              key={i}
              className="rounded border border-gray-200 bg-white p-2 space-y-1.5"
            >
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={f.name}
                  onChange={(e) => updateAt(i, { name: e.target.value })}
                  placeholder="analyze.py"
                  className={`flex-1 rounded border px-2 py-1 font-mono text-sm ${
                    nameInvalid ? 'border-red-400' : 'border-gray-300'
                  }`}
                  aria-label="Inline file name"
                />
                <span className="shrink-0 text-[11px] text-gray-400 tabular-nums">
                  {humanSize(new Blob([f.content]).size)}
                </span>
                <button
                  type="button"
                  onClick={() => removeAt(i)}
                  className="shrink-0 rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-600 hover:border-red-400 hover:text-red-700"
                  aria-label="Remove inline file"
                  title="Remove"
                >
                  ✕
                </button>
              </div>
              {errMsg && (
                <p className="text-[11px] text-red-700">{errMsg}</p>
              )}
              <textarea
                value={f.content}
                onChange={(e) => updateAt(i, { content: e.target.value })}
                spellCheck={false}
                rows={8}
                className="w-full resize-y rounded border border-gray-300 px-3 py-2 font-mono text-xs"
                placeholder={
                  trimmedName.endsWith('.py')
                    ? '#!/usr/bin/env python3\n# Your script…'
                    : '# Your file contents…'
                }
              />
            </div>
          );
        })
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
// slugify produces a template-id-safe identifier from arbitrary
// human input: lowercase, non-alphanumeric runs collapsed to single
// hyphens, leading/trailing hyphens stripped. Used to seed the
// dialog's id field from the agent's suggestion or the draft name —
// the user can still hand-edit the result before saving.
function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// countOccurrences counts non-overlapping literal matches of `needle`
// in `haystack`. Used by replace_in_inline_file to refuse ambiguous
// edits — if the agent's find string matches >1 place, we want to
// surface that instead of silently editing the first match.
function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let from = 0;
  while (true) {
    const idx = haystack.indexOf(needle, from);
    if (idx < 0) return count;
    count++;
    from = idx + needle.length;
  }
}

// listAllInlineNames returns every name the inline-file editor knows
// about — the wrapper script + the additional inline files. Used in
// chat-tool error responses so the agent can quickly orient when it
// asks for a file by the wrong name ("did you mean wrapper.sh or
// analyze.py?").
function listAllInlineNames(d: CustomDraft): string[] {
  const out: string[] = [];
  if (d.inlineScript && d.inlineScript.name.trim() !== '') {
    out.push(d.inlineScript.name.trim());
  }
  for (const f of d.inlineFiles) {
    const n = f.name.trim();
    if (n) out.push(n);
  }
  return out;
}

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
  count,
  setCount,
}: {
  columns: TemplateColumn[];
  rows: string[][];
  setRows: (r: string[][]) => void;
  source: TableSource;
  setSource: (s: TableSource) => void;
  uploadFiles: DroppedFile[];
  setUploadFiles: (f: DroppedFile[]) => void;
  count: number;
  setCount: (n: number) => void;
}) {
  const columnNames = columns.map((c) => c.name);
  // Count mode is always available even when the template has no
  // columns — that's the single-job fallback the page used to render
  // hardcoded; we now expose it as the explicit "Run N copies" option.
  const subtitle =
    source === 'count'
      ? `Will submit ${Math.max(1, Math.floor(count) || 1)} cop${count === 1 ? 'y' : 'ies'} of the template.`
      : source === 'upload'
        ? `One job per file from the upload. ${uploadFiles.length} file${uploadFiles.length === 1 ? '' : 's'} loaded.`
        : columns.length === 0
          ? 'This template has no variable columns; one row = one job.'
          : `Column headers come from the template. ${rows.length} row${rows.length === 1 ? '' : 's'} = ${rows.length} job${rows.length === 1 ? '' : 's'}.`;
  return (
    <SectionCard title="2. Table" subtitle={subtitle}>
      {/* Source toggle: manual table / fixed count / directory upload.
          The count mode is always available; the other two require at
          least one column on the template. */}
      <div className="mb-3 inline-flex flex-wrap rounded-md border border-gray-300 bg-white p-0.5 text-sm">
        {columns.length > 0 && (
          <ModeButton active={source === 'manual'} onClick={() => setSource('manual')}>
            Manual table
          </ModeButton>
        )}
        <ModeButton active={source === 'count'} onClick={() => setSource('count')}>
          Run N copies
        </ModeButton>
        {columns.length > 0 && (
          <ModeButton active={source === 'upload'} onClick={() => setSource('upload')}>
            From directory / tarball
          </ModeButton>
        )}
      </div>

      {source === 'count' ? (
        <CountSource count={count} setCount={setCount} />
      ) : columns.length === 0 ? (
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
// CountSource is the "Run N copies" alternative to the per-job table.
// Renders a single integer input bound to `count`. The parent
// synthesizes `queue N` at submit time. Useful when each job needs
// only ProcId-based variation (typical Monte Carlo / stress-test /
// "just run it" patterns) and a per-job table would be busy work.
function CountSource({
  count,
  setCount,
}: {
  count: number;
  setCount: (n: number) => void;
}) {
  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2 text-sm">
        <span className="text-gray-700">Number of jobs:</span>
        <input
          type="number"
          min={1}
          max={MAX_TABLE_COUNT}
          step={1}
          value={count}
          onChange={(e) => {
            const n = parseInt(e.target.value, 10);
            setCount(Number.isFinite(n) && n >= 1 ? n : 1);
          }}
          className="w-24 rounded border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
        />
      </label>
      <p className="text-xs text-gray-500">
        Each job runs the same submit-file body. Reference{' '}
        <code>$(ProcId)</code> in the body (0 to N&minus;1) to differentiate
        them.
      </p>
    </div>
  );
}

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
// Resources section: Step 4. Per-field overrides — the user picks
// which of cpus / memory / disk / gpus to override; the rest inherit
// from the template body. Defaults are computed in the parent so
// fields the template is silent on are checked by default (otherwise
// the schedd would have nothing to plan against), and fields the
// template already covers are unchecked by default (so we don't
// silently rewrite a deliberate template choice).
// ----------------------------------------------------------------------

function ResourcesSection({
  templateContents,
  fields,
  setFields,
  resources,
  setResources,
}: {
  templateContents: string;
  fields: ResourceFieldMask;
  setFields: React.Dispatch<React.SetStateAction<ResourceFieldMask>>;
  resources: ResourceRequest;
  setResources: (r: ResourceRequest) => void;
}) {
  const tplValues = useMemo(
    () => readResourcesFromBody(templateContents),
    [templateContents],
  );
  const tplHas = (key: string) =>
    getAttribute(templateContents, key) !== undefined;
  const anyChecked =
    fields.cpus || fields.memory || fields.disk || fields.gpus;

  // Subtitle reflects what's actually about to happen at submit
  // time. If the user has flipped at least one box on, we say so;
  // otherwise we describe what will be inherited (or what's missing).
  const subtitle = anyChecked
    ? 'Overriding the checked fields below; unchecked fields inherit from the template body.'
    : tplHas('request_cpus') || tplHas('request_memory') || tplHas('request_disk')
      ? 'Inheriting all values from the template body. Tick a field to override just that one.'
      : 'No resource requests will be sent and the schedd will fall back to its pool-wide defaults. Tick a field to set it explicitly.';

  return (
    <SectionCard title="4. Resources" subtitle={subtitle}>
      <div className="space-y-3">
        <ResourceFieldRow
          label="CPUs"
          checked={fields.cpus}
          onChecked={(b) => setFields((p) => ({ ...p, cpus: b }))}
          inheritedHint={
            tplHas('request_cpus') ? `template: ${tplValues.cpus}` : 'template: not set'
          }
        >
          <input
            type="number"
            min={1}
            max={64}
            value={resources.cpus}
            disabled={!fields.cpus}
            onChange={(e) =>
              setResources({
                ...resources,
                cpus: clampInt(e.target.value, 1, 64, resources.cpus),
              })
            }
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-100 disabled:text-gray-400"
          />
        </ResourceFieldRow>

        <ResourceFieldRow
          label="Memory (MiB)"
          checked={fields.memory}
          onChecked={(b) => setFields((p) => ({ ...p, memory: b }))}
          inheritedHint={
            tplHas('request_memory')
              ? `template: ${tplValues.memoryMB} MiB`
              : 'template: not set'
          }
        >
          <input
            type="number"
            min={256}
            step={256}
            value={resources.memoryMB}
            disabled={!fields.memory}
            onChange={(e) =>
              setResources({
                ...resources,
                memoryMB: clampInt(e.target.value, 256, undefined, resources.memoryMB),
              })
            }
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-100 disabled:text-gray-400"
          />
        </ResourceFieldRow>

        <ResourceFieldRow
          label="Disk (MiB)"
          checked={fields.disk}
          onChecked={(b) => setFields((p) => ({ ...p, disk: b }))}
          inheritedHint={
            tplHas('request_disk')
              ? `template: ${tplValues.diskMB} MiB`
              : 'template: not set'
          }
        >
          <input
            type="number"
            min={256}
            step={256}
            value={resources.diskMB}
            disabled={!fields.disk}
            onChange={(e) =>
              setResources({
                ...resources,
                diskMB: clampInt(e.target.value, 256, undefined, resources.diskMB),
              })
            }
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-100 disabled:text-gray-400"
          />
        </ResourceFieldRow>

        <ResourceFieldRow
          label="GPUs"
          checked={fields.gpus}
          onChecked={(b) => setFields((p) => ({ ...p, gpus: b }))}
          inheritedHint={
            tplHas('request_gpus')
              ? `template: ${tplValues.gpus}`
              : 'template: not set'
          }
        >
          <input
            type="number"
            min={0}
            max={16}
            value={resources.gpus}
            disabled={!fields.gpus}
            onChange={(e) =>
              setResources({
                ...resources,
                gpus: clampInt(e.target.value, 0, 16, resources.gpus),
              })
            }
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-100 disabled:text-gray-400"
          />
        </ResourceFieldRow>

        {/* GPU subfields only matter when the GPU override is on AND
            the user is asking for at least one GPU. The shared
            ResourceRequestPanel renders them; we reuse it for the
            subfield-only case by hiding its CPU/memory/disk row via
            CSS. Cleaner long-term might be to factor the subfields
            out, but for this iteration the visual hide keeps the
            change small and the GPU UX consistent with the
            interactive page. */}
        {fields.gpus && resources.gpus > 0 && (
          <div className="ml-7 mt-2 rounded border border-gray-200 bg-gray-50 p-3">
            <ResourceRequestPanel
              value={resources}
              onChange={setResources}
              gpuSubfieldsOnly
            />
          </div>
        )}
      </div>
    </SectionCard>
  );
}

// ResourceFieldRow is one row in the per-field override list — a
// leading checkbox + the field's input + an inheritance hint.
// Disabled inputs (when the checkbox is unchecked) keep the value
// visible but read-only so the user can re-enable without retyping.
//
// The input slot is a fixed-width column (`w-32 shrink-0`) so the
// hint text starts at the same x across CPUs / Memory / Disk / GPUs
// rows regardless of how many digits the input wants room for. The
// individual inputs use `w-full` to fill the slot.
function ResourceFieldRow({
  label,
  checked,
  onChecked,
  inheritedHint,
  children,
}: {
  label: string;
  checked: boolean;
  onChecked: (v: boolean) => void;
  inheritedHint: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3 text-sm">
      <label className="inline-flex items-center gap-2 w-44 shrink-0 text-gray-700">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChecked(e.target.checked)}
          className="rounded border-gray-300"
        />
        {label}
      </label>
      <div className="w-32 shrink-0">{children}</div>
      <span className="text-[11px] text-gray-400 truncate">{inheritedHint}</span>
    </div>
  );
}

// clampInt is the same input-clamp used by ResourceRequestPanel —
// duplicated here to keep the per-field rows self-contained without
// reaching into an internal helper.
function clampInt(
  raw: string,
  min: number | undefined,
  max: number | undefined,
  fallback: number,
): number {
  const n = parseInt(raw, 10);
  if (Number.isNaN(n)) return fallback;
  if (min !== undefined && n < min) return min;
  if (max !== undefined && n > max) return max;
  return n;
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

// buildSubmitFileWithCount appends a flat `queue N` to the body. Used
// for `tableSource === 'count'` where the user wants N copies of the
// same job (typical for stress tests, parameter sweeps that vary by
// $(ProcId), or one-off "just run it" cases).
function buildSubmitFileWithCount(contents: string, count: number): string {
  const n = Math.max(1, Math.floor(count) || 1);
  return `${contents.trimEnd()}\nqueue ${n}\n`;
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

// groupTemplatesForPicker is the dropdown's filtered + grouped view.
// Differs from groupBySource: user-source templates split into "Mine"
// (owner == current user) vs. "Shared by others" (owner != current
// user, visibility == "shared"). The split makes it obvious in the
// picker what you can edit/delete vs. what someone else owns.
function groupTemplatesForPicker(
  list: Template[],
  currentUser: string,
): { label: string; items: Template[] }[] {
  const mine: Template[] = [];
  const shared: Template[] = [];
  const global: Template[] = [];
  const builtin: Template[] = [];
  for (const t of list) {
    if (t.source === 'user') {
      if (!t.owner || t.owner === currentUser) mine.push(t);
      else shared.push(t);
    } else if (t.source === 'global') {
      global.push(t);
    } else {
      builtin.push(t);
    }
  }
  const out: { label: string; items: Template[] }[] = [];
  if (mine.length) out.push({ label: 'My templates', items: mine });
  if (shared.length) out.push({ label: 'Shared by others', items: shared });
  if (global.length) out.push({ label: 'Site templates', items: global });
  if (builtin.length) out.push({ label: 'Built-in', items: builtin });
  return out;
}

// TemplateCombobox is a typeahead picker that replaces the native
// <select> + <optgroup> arrangement. Type to filter against the
// template name, owner, and description (case-insensitive substring).
// Arrow keys navigate; Enter selects; Esc closes. Each row shows the
// name + source badge; for "Shared by others" rows it also shows
// "by <owner>" so the user can disambiguate same-named templates.
function TemplateCombobox({
  templates,
  selectedID,
  setSelectedID,
  currentUser,
  placeholder,
}: {
  templates: Template[];
  selectedID: string;
  setSelectedID: (id: string) => void;
  currentUser: string;
  // Trigger label when nothing is selected. Defaults to "Select a
  // template…". The clone-from picker passes "Start from a copy of…"
  // and pairs it with selectedID="" to get the same combobox in
  // "one-shot" mode (each pick triggers an action, the trigger
  // never reflects a stable selection).
  placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const selected = templates.find((t) => t.id === selectedID);
  const triggerLabel = selected
    ? selected.name
    : placeholder ?? 'Select a template…';

  // Flat filtered list (already in group order). We render groups
  // visually but the keyboard nav needs to work over a single index
  // space, so we always keep the flat ordering as the source of
  // truth and stamp groups on the side for rendering.
  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = (t: Template): boolean => {
      if (q === '') return true;
      if (t.name.toLowerCase().includes(q)) return true;
      if ((t.description ?? '').toLowerCase().includes(q)) return true;
      if (t.owner && t.owner.toLowerCase().includes(q)) return true;
      return false;
    };
    return groupTemplatesForPicker(
      templates.filter(matches),
      currentUser,
    );
  }, [templates, query, currentUser]);
  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);

  // Reset the highlighted row whenever the filter changes — the old
  // index can point past the filtered list otherwise.
  useEffect(() => {
    setActiveIdx(0);
  }, [query]);

  // Click-outside to close.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    window.addEventListener('mousedown', onClick);
    return () => window.removeEventListener('mousedown', onClick);
  }, [open]);

  const choose = (t: Template) => {
    setSelectedID(t.id);
    setQuery('');
    setOpen(false);
  };

  return (
    <div ref={containerRef} className="relative">
      {!open ? (
        <button
          type="button"
          onClick={() => {
            setOpen(true);
            setQuery('');
            // Focus the input on the next tick — it doesn't exist
            // until `open` flips and the input renders.
            setTimeout(() => inputRef.current?.focus(), 0);
          }}
          className="mt-1 flex w-full items-center justify-between rounded border border-gray-300 bg-white px-3 py-1.5 text-left text-sm hover:border-gray-400"
        >
          <span className="flex items-center gap-2 truncate">
            <span className={selected ? 'text-gray-900' : 'text-gray-400'}>
              {triggerLabel}
            </span>
            {selected && <SourceBadge source={selected.source} />}
            {selected && selected.owner && selected.owner !== currentUser && (
              <span className="text-xs text-gray-500">
                by {selected.owner}
              </span>
            )}
          </span>
          <span aria-hidden className="ml-2 text-gray-400">
            ▾
          </span>
        </button>
      ) : (
        <input
          ref={inputRef}
          type="text"
          value={query}
          placeholder="Type to filter by name, owner, or description…"
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault();
              setActiveIdx((i) => Math.min(flat.length - 1, i + 1));
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              setActiveIdx((i) => Math.max(0, i - 1));
            } else if (e.key === 'Enter') {
              e.preventDefault();
              const t = flat[activeIdx];
              if (t) choose(t);
            } else if (e.key === 'Escape') {
              e.preventDefault();
              setOpen(false);
            }
          }}
          className="mt-1 w-full rounded border border-brand-400 bg-white px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-brand-400"
        />
      )}
      {open && (
        <div className="absolute left-0 right-0 z-10 mt-1 max-h-72 overflow-y-auto rounded border border-gray-300 bg-white shadow-lg">
          {flat.length === 0 ? (
            <p className="px-3 py-2 text-xs text-gray-500">
              No templates match.
            </p>
          ) : (
            (() => {
              let cursor = 0;
              return groups.map((g) => (
                <div key={g.label}>
                  <div className="bg-gray-50 px-3 py-1 text-[10px] uppercase tracking-wide text-gray-500">
                    {g.label}
                  </div>
                  {g.items.map((t) => {
                    const idx = cursor++;
                    const isActive = idx === activeIdx;
                    const isCurrent = t.id === selectedID;
                    return (
                      <button
                        key={`${t.source}:${t.owner ?? ''}:${t.id}`}
                        type="button"
                        onMouseEnter={() => setActiveIdx(idx)}
                        onClick={() => choose(t)}
                        className={`flex w-full items-baseline gap-2 px-3 py-1.5 text-left text-sm ${
                          isActive ? 'bg-brand-50' : 'bg-white'
                        } ${isCurrent ? 'font-medium' : ''}`}
                      >
                        <span className="truncate">{t.name}</span>
                        <SourceBadge source={t.source} />
                        {t.owner && t.owner !== currentUser && (
                          // Amber-tinted "by <owner>" pill so
                          // shared-by-others rows stand out from "Mine"
                          // and built-ins. Mirrors the banner shown
                          // after selection — ditto the security-audit
                          // motivation.
                          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-800">
                            by {t.owner}
                          </span>
                        )}
                        {t.description && (
                          <span className="ml-auto truncate text-[11px] text-gray-400">
                            {t.description}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ));
            })()
          )}
        </div>
      )}
    </div>
  );
}
