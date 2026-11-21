# gdrive2: a Google Drive transfer plugin addressed by file ID

Destined for upstream HTCondor. It lives here while it is proven against a
real access point; nothing in golang-htcondor imports it.

## Why

HTCondor already ships `src/condor_scripts/gdrive_plugin.py`, and it is
deployed everywhere — measured 2026-11-21, every one of 14,552 CHTC slots
across 260 machines advertises the `gdrive` method, as do all 246 PATh
Facility slots, so a job opting into the OSPool keeps it.

That plugin addresses files by **path** and resolves the path by **listing**
Drive, walking down from the root. Listing needs a broad Drive scope.

The narrow scope, `drive.file`, grants an application access only to the
files a user explicitly picked for it through the Google Picker, or that it
created itself. It is the right scope for a file picker — picking *is* the
grant — and under it the stock plugin cannot work, because it cannot see the
folders on the way to a file it can perfectly well read.

Two independent reasons to want the narrow scope:

- **Blast radius.** In a direct transfer the token sits in `$_CONDOR_CREDS`
  on an execute node, which on a shared pool is a machine the submitter does
  not control. A leaked `drive.readonly` token exposes the user's whole
  Drive; a leaked `drive.file` token exposes the files they picked for that
  job.
- **Compliance.** Broad Drive scopes are "restricted" and oblige the
  application to an annual third-party security assessment. `drive.file` is
  not restricted.

The first reason is sufficient on its own.

## The upload bug it also fixes

The stock plugin's upload path calls

```python
get_parent_folders_ids(folder_tree, create_if_missing = True)
```

Under `drive.file` it cannot see the user's existing `MyProject/results/`,
so `create_if_missing` does what it says: it makes a **second one, owned by
the application**, shadowing the real folder. Output lands somewhere that
looks correct in the plugin's own logs and is not where the user expected.

A silent wrong answer, not an error. This plugin never creates a folder and
never walks a path.

## URL forms

```
gdrive2://<fileId>/<name>      download that file, saved as <name>
gdrive2://<folderId>/<name>    upload, creating or replacing <name> there
gdrive2:///<name>              upload into My Drive root
<cred>+gdrive2://...           read the credential <cred>.use, verbatim
```

`<name>` has to be in the URL even though Drive identifies the file by ID,
because HTCondor takes the job's local file name from it — "the destination
file is given by the file name within the URL"
(`docs/users-manual/file-transfer.rst:703`).

A URL with more than one path component is **refused**, not reinterpreted.
Under `drive.file` the only thing this plugin could do with a path is guess.

## Two names that are not the same name

The **method** is `gdrive2`. The **credential** defaults to `gdrive`.

A job says `use_oauth_services = gdrive` whichever plugin it uses. Naming the
credential after the plugin would oblige every user to hold a second,
identical Google credential under a second name — a second consent screen and
a second grant to revoke, for nothing but a version number.

A URL may name its credential outright: `<cred>+gdrive2://` reads
`<cred>.use`, **verbatim**. The stock plugin reads the same syntax as the
*composed* name `<provider>_<handle>`, and the difference is deliberate. A
server that provisions credentials into a credd it shares with an
administrator has to store them under a service name of its own —
`webapi_gdrive`, say, so as not to collide with the administrator's
`gdrive` — and the composing form cannot reach that name: it would need the
provider half to be `webapi`, which is not a transfer method.

The two plugins never see the same URL, because the methods differ, so no
URL is ambiguous between them. That is only true while this plugin does not
claim `gdrive`.

The method is deliberately *not* `gdrive`. A job can carry its own plugin
(`transfer_plugins`), and claiming a method the stock plugin already
advertises would collide with it on every execute node — which, per the
measurement above, is all of them. A distinct method lets a single job try
this on unmodified machines before anything is deployed anywhere.

## Trying it without deploying anything

```
transfer_plugins       = gdrive2=gdrive2_plugin.py
transfer_input_files   = gdrive2_plugin.py, gdrive2://<fileId>/input.csv
use_oauth_services     = gdrive
```

Whether a job-supplied plugin may claim a method name that no stock plugin
advertises is the only part of this not yet confirmed against a real pool.

## Tests

```sh
python3 -m unittest test_gdrive2_plugin -v
```

23 tests against a stand-in Drive API on localhost — no network, no Google
account, no credential. Needs `requests` and HTCondor's `classad2`.

Ten mutants were checked and each is killed by a named test: uploading
always-create (duplicates), setting `parents` on an update, caching the
token in memory, naming the credential after the plugin, composing
`<provider>_<cred>` instead of reading it verbatim, silently accepting
paths, dropping retry, leaking `TransferUrl` into the transfer history,
dropping the 404 diagnosis, and trusting Drive's `name=` match without
re-checking it.

## What upstream may want to change

Folding ID addressing into the existing `gdrive` method instead of adding
one, using an empty authority (`gdrive:///<id>/<name>`) to tell the two forms
apart. That is a better end state. It is a worse way to get there, because
until it has shipped everywhere there is no way to try it on a real pool.

Google-native documents (Docs, Sheets, Slides) have no bytes to download and
need `/export` with a chosen MIME type. This plugin detects them and says so
rather than failing obscurely, but does not export them.
