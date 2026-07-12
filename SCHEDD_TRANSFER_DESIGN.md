# File Transfer Protocol Design

This document describes the HTCondor file transfer protocol implementation for the golang-htcondor library, specifically for the `ReceiveJobSandbox` and `SpoolJobFiles` operations.

## Overview

HTCondor uses a custom file transfer protocol built on top of CEDAR for transferring job input and output files. This protocol is used in two primary scenarios:

1. **ReceiveJobSandbox (Download)**: Download output files from completed jobs
2. **SpoolJobFiles (Upload)**: Upload input files for jobs to be submitted

## References

The implementation is based on the following C++ code in the `reference/` directory:

- `dc_schedd.cpp`: High-level schedd operations (`DCSchedd::receiveJobSandbox`, `DCSchedd::spoolJobFiles`)
- `file_transfer.cpp`: Low-level file transfer protocol (`FileTransfer::DoDownload`, `FileTransfer::DoUpload`)
- `transfer_data.cpp`: Command-line tool demonstrating the download protocol

## ReceiveJobSandbox Protocol

### Purpose

Downloads output files (job sandbox) for jobs matching a constraint expression. Used by tools like `condor_transfer_data`.

### Command

- `TRANSFER_DATA_WITH_PERMS` (SCHED_VERS + 89)
- Older versions use `TRANSFER_DATA` (SCHED_VERS + 86) without file permissions

### Protocol Flow

```
Client                              Schedd
  |                                   |
  |-- TRANSFER_DATA_WITH_PERMS ------>|
  |<-- DC_AUTHENTICATE handshake ---->|
  |                                   |
  |-- Version String ---------------->|
  |-- Constraint Expression --------->|
  |-- EOM --------------------------->|
  |                                   |
  |<-- Number of Jobs (int) ----------|
  |<-- EOM ----------------------------|
  |                                   |
  | For each job:                     |
  |<-- Job ClassAd --------------------|
  |<-- EOM ----------------------------|
  |<-- File Transfer Stream -----------|
  |                                   |
  |-- OK Reply (0) ------------------->|
  |-- EOM --------------------------->|
```

### Message Details

1. **Version String**: HTCondor version string (e.g., "$GIT" or actual version)
2. **Constraint**: ClassAd constraint expression (e.g., "ClusterId == 123")
3. **Number of Jobs**: Integer count of jobs matching the constraint
4. **Job ClassAd**: Full job ClassAd for each matching job
   - Contains `ClusterId` and `ProcId` for identification
   - May contain `SUBMIT_*` attributes that should be translated (strip `SUBMIT_` prefix)
5. **File Transfer Stream**: See "File Transfer Commands" section below

### Job Ad Translation

The job ClassAd may contain `SUBMIT_*` attributes that were saved from the submit file. These should be translated by:
- Iterating through all attributes with `SUBMIT_` prefix
- Creating new attributes with the same values but without the prefix
- Example: `SUBMIT_Executable` → `Executable`

### Output Format

Files should be organized in a tar archive structure:
```
cluster.proc/
  ├── stdout
  ├── stderr
  ├── output_file1.txt
  └── subdirectory/
      └── output_file2.dat
```

## SpoolJobFiles Protocol

### Purpose

Uploads input files to the schedd for jobs that will be submitted. Used during job submission to spool files to the schedd's spool directory.

### Command

- `SPOOL_JOB_FILES_WITH_PERMS` (SCHED_VERS + 88)
- Older versions use `SPOOL_JOB_FILES` (SCHED_VERS + 80) without file permissions

### Protocol Flow

```
Client                              Schedd
  |                                   |
  |-- SPOOL_JOB_FILES_WITH_PERMS ---->|
  |<-- DC_AUTHENTICATE handshake ---->|
  |                                   |
  |-- Version String ---------------->|
  |-- Number of Jobs (int) ---------->|
  |-- EOM --------------------------->|
  |                                   |
  | For each job:                     |
  |-- PROC_ID (cluster, proc) ------->|
  |-- EOM --------------------------->|
  |                                   |
  | For each job:                     |
  |-- File Transfer Stream ---------->|
  |-- EOM --------------------------->|
  |                                   |
  |<-- Reply (1=success, 0=fail) ------|
  |<-- EOM ----------------------------|
```

### Message Details

1. **Version String**: HTCondor version string
2. **Number of Jobs**: Integer count of jobs to spool files for
3. **PROC_ID Structure**: For each job:
   - Cluster ID (int32)
   - Proc ID (int32)
4. **File Transfer Stream**: See "File Transfer Commands" section below
5. **Reply**: 1 = success, 0 = failure

### Input File Discovery

Files to transfer are determined from job ClassAd attributes:
- `TransferInput`: Comma-separated list of input files
- Files are relative to the submit directory or absolute paths

## File Transfer Commands

Both download and upload operations use the same set of transfer commands to describe the file operations.

### Transfer Command Codes

```go
const (
    CommandFinished          = 0   // End of transfer
    CommandXferFile          = 1   // Transfer a file
    CommandEnableEncryption  = 2   // Enable encryption for next file
    CommandDisableEncryption = 3   // Disable encryption for next file
    CommandXferX509          = 4   // Transfer X.509 credential
    CommandDownloadURL       = 5   // Download from URL
    CommandMkdir             = 6   // Create directory
    CommandOther             = 999 // Plugin-specific command
)
```

### CommandXferFile (1) - File Transfer

Used to transfer a single file.

**Upload (Client → Schedd):**
```
Client                              Schedd
  |-- CommandXferFile (1) ---------->|
  |-- EOM --------------------------->|
  |-- Filename (string) -------------->|
  |-- EOM --------------------------->|
  |-- File Size (int64) -------------->|
  |-- EOM --------------------------->|
  |-- File Permissions (int64) ------->| (if *_WITH_PERMS)
  |-- EOM --------------------------->|
  |-- File Data (bytes) -------------->|
  |-- EOM --------------------------->|
```

**Download (Schedd → Client):**
Same format, but schedd sends to client.

**Details:**
- **Filename**: Relative path of the file (e.g., "input.txt" or "subdir/file.dat")
- **File Size**: Size in bytes (int64)
- **File Permissions**: Unix file mode (e.g., 0644, 0755) - only with `*_WITH_PERMS` commands
- **File Data**: Raw file contents

### CommandMkdir (6) - Create Directory

Used to create a directory in the sandbox.

```
  |-- CommandMkdir (6) --------------->|
  |-- EOM --------------------------->|
  |-- Directory Name (string) -------->|
  |-- EOM --------------------------->|
```

**Details:**
- **Directory Name**: Relative path (e.g., "subdir" or "path/to/dir")
- Directories are created with default permissions (0755)

### CommandDownloadURL (5) - URL Download

Instructs the receiver to download a file from a URL.

```
  |-- CommandDownloadURL (5) --------->|
  |-- EOM --------------------------->|
  |-- URL (string) ------------------->|
  |-- EOM --------------------------->|
```

**Details:**
- Used for large files or files available via HTTP/HTTPS
- Receiver is responsible for downloading the file
- Not commonly used in basic implementations

### CommandFinished (0) - End of Transfer

Signals that all files for the current job have been transferred.

```
  |-- CommandFinished (0) ------------>|
  |-- EOM --------------------------->|
```

**Details:**
- Sent after all files for a job
- In multi-job transfers, sent after each job's files
- Final CommandFinished marks end of entire transfer

### CommandOther (999) - Plugin Commands

Used for transfer plugin operations (advanced feature).

```
  |-- CommandOther (999) -------------->|
  |-- EOM --------------------------->|
  |-- Filename (string) -------------->|
  |-- EOM --------------------------->|
  |-- ClassAd (with plugin info) ------>|
  |-- EOM --------------------------->|
```

**SubCommands** (in ClassAd):
- `7` - UploadUrl: Plugin uploaded file to URL
- `8` - ReuseInfo: Files eligible for reuse
- `9` - SignUrls: Request URL signing

## Authentication

Both protocols require DC_AUTHENTICATE handshake using the `security` package:

```go
secConfig := &security.SecurityConfig{
    Command:        commands.TRANSFER_DATA_WITH_PERMS, // or SPOOL_JOB_FILES_WITH_PERMS
    AuthMethods:    []security.AuthMethod{security.AuthFS, security.AuthSSL},
    Authentication: security.SecurityRequired,
    CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
    Encryption:     security.SecurityOptional,
    Integrity:      security.SecurityOptional,
}

auth := security.NewAuthenticator(secConfig, cedarStream)
_, err := auth.ClientHandshake(ctx)
```

## Error Handling

### Transfer Errors

Errors can occur at various points:
- Connection failures
- Authentication failures
- Protocol errors (unexpected data)
- File I/O errors
- Disk space issues

### Error Reporting

In upload operations, the schedd sends a reply code:
- `1` = Success
- `0` = Failure

For downloads, the client sends an OK reply:
- `0` = Success
- Non-zero = Error code

## Implementation Considerations

### Message Framing

Each logical message is followed by EOM (End of Message):
- Use `msg.FinishMessage(ctx)` to send EOM
- Messages are automatically framed by the CEDAR protocol

### Large Files

For large files:
- Consider streaming data instead of loading into memory
- Use `io.Copy` to transfer data efficiently
- Implement progress tracking for user feedback

### Tar Archive Format

When writing files to tar:
- Use `archive/tar` package
- Organize files by job: `cluster.proc/filename`
- Include directory entries before files in them
- Set appropriate file permissions

### Concurrency

The `ReceiveJobSandbox` method starts a goroutine:
- Returns immediately with a channel
- Caller reads from channel to get final result
- This allows long-running transfers without blocking

### Resource Cleanup

Always clean up resources:
```go
defer func() {
    _ = conn.Close()
    _ = tarWriter.Close()
}()
```

## Future Enhancements

Features not yet implemented but documented in the C++ code:

1. **Transfer Plugins**: External programs for custom transfer methods
2. **URL Transfers**: Download from HTTP/HTTPS URLs
3. **Transfer Queue**: Bandwidth throttling and fair sharing
4. **Encryption Control**: Dynamic encryption enable/disable per file
5. **X.509 Credentials**: Transfer delegated credentials
6. **File Reuse**: Avoid re-transferring unchanged files
7. **Checkpoint Files**: Special handling for checkpoint files
8. **Compression**: Compress files during transfer

## Testing

When implementing, test with:

1. **Single File**: Basic transfer of one file
2. **Multiple Files**: Transfer of several files
3. **Directories**: Files in subdirectories
4. **Large Files**: Files > 1MB to test streaming
5. **Empty Files**: Zero-byte files
6. **Special Characters**: Files with spaces, unicode in names
7. **Permissions**: Various file permissions (executable, read-only)
8. **Error Cases**: Network errors, permission errors, disk full

## Example Usage

### Download Job Output

```go
// Download output files for a specific cluster
constraint := "ClusterId == 123"
var buf bytes.Buffer

errChan := schedd.ReceiveJobSandbox(ctx, constraint, &buf)
err := <-errChan
if err != nil {
    log.Fatalf("Transfer failed: %v", err)
}

// Extract tar archive
tarReader := tar.NewReader(&buf)
// ... extract files
```

### Upload Job Input

```go
// Upload input files for submitted jobs
jobAds := []*classad.ClassAd{jobAd1, jobAd2}
fsys := os.DirFS("/path/to/submit/dir")

err := schedd.SpoolJobFilesFromFS(ctx, jobAds, fsys)
if err != nil {
    log.Fatalf("Upload failed: %v", err)
}
```

## See Also

- `FILE_TRANSFER_DESIGN.md`: Original file transfer design document
- `reference/dc_schedd.cpp`: C++ implementation
- `reference/file_transfer.cpp`: File transfer protocol details
- `reference/transfer_data.cpp`: Command-line tool example
