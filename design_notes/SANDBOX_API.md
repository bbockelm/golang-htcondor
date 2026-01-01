# Sandbox API Design

## Overview

The sandbox API provides two complementary operations for managing HTCondor job sandboxes:

1. **Input Sandbox Creation**: Given a job ad, create a tarball containing all input files
2. **Output Sandbox Extraction**: Given a job ad and a tarball, extract output files to their proper locations

These operations mimic the logic that the HTCondor shadow performs when:
- Sending input sandboxes to the starter (before job execution)
- Receiving output sandboxes from the starter (after job completion)

## API Design

```go
package sandbox

import (
    "context"
    "io"
    "github.com/PelicanPlatform/classad/classad"
)

// CreateInputSandboxTar creates a tarball containing all input files specified in the job ad.
// The tarball layout matches what the shadow sends to the starter.
//
// Parameters:
//   - ctx: Context for cancellation
//   - jobAd: Job ClassAd containing TransferInput, Iwd, and related attributes
//   - w: Writer where the tar archive will be written
//
// Returns error if files cannot be read or tar cannot be created.
func CreateInputSandboxTar(ctx context.Context, jobAd *classad.ClassAd, w io.Writer) error

// ExtractOutputSandbox extracts files from an output sandbox tarball and places them
// in the appropriate locations based on the job ad.
//
// Parameters:
//   - ctx: Context for cancellation
//   - jobAd: Job ClassAd containing TransferOutput, TransferOutputRemaps, Iwd, etc.
//   - r: Reader providing the tar archive
//
// Returns error if extraction fails or files cannot be written.
func ExtractOutputSandbox(ctx context.Context, jobAd *classad.ClassAd, r io.Reader) error
```

## Input Sandbox Details

### Job Ad Attributes

The input sandbox uses these job ad attributes:

- **`TransferInput`**: Comma-separated list of input files to transfer (from `transfer_input_files` in submit file)
- **`Iwd`**: Initial working directory - base path for relative file references
- **`TransferExecutable`**: Boolean indicating whether to transfer the executable
- **`Cmd`**: Path to the executable file

### Example Job Ad

```classad
[
    ClusterId = 123;
    ProcId = 0;
    Iwd = "/home/user/myproject";
    Cmd = "/home/user/myproject/my_script.sh";
    TransferExecutable = true;
    TransferInput = "input.txt,data/params.json,shared/config.cfg";
]
```

### Filesystem Layout

Given the job ad above, assume the following files exist:

```
/home/user/myproject/
  my_script.sh          (executable, 755)
  input.txt             (regular file, 644)
  data/
    params.json         (regular file, 644)
  shared/
    config.cfg          (regular file, 644)
```

### Tarball Layout

The generated tarball should contain:

```
my_script.sh           (from Cmd, mode 755)
input.txt              (from TransferInput, mode 644)
data/params.json       (preserves directory structure, mode 644)
shared/config.cfg      (preserves directory structure, mode 644)
```

**Key Points:**
- All paths in the tarball are relative to the job's working directory
- Directory structure is preserved for files in subdirectories
- The executable is included if `TransferExecutable = true`
- File permissions are preserved
- Absolute paths in `TransferInput` are made relative to the tarball root

### Handling Absolute Paths

If a file is specified with an absolute path outside `Iwd`:

```classad
[
    Iwd = "/home/user/myproject";
    TransferInput = "/tmp/external_data.txt,input.txt";
]
```

The tarball should flatten external absolute paths:

```
external_data.txt      (from /tmp/external_data.txt)
input.txt              (from /home/user/myproject/input.txt)
```

Or alternatively, preserve the full path structure within the tarball (HTCondor behavior to be confirmed).

## Output Sandbox Details

### Job Ad Attributes

The output sandbox uses these job ad attributes:

- **`TransferOutput`**: Comma-separated list of output files to transfer (from `transfer_output_files` in submit file)
- **`TransferOutputRemaps`**: Semicolon-separated list of `src=dest` remappings
- **`Iwd`**: Initial working directory - where files are written by default
- **`Out`**: Standard output file path (if not `/dev/null`)
- **`Err`**: Standard error file path (if not `/dev/null`)

### Example Job Ad

```classad
[
    ClusterId = 123;
    ProcId = 0;
    Iwd = "/home/user/myproject";
    TransferOutput = "output.txt,results/data.json";
    TransferOutputRemaps = "output.txt=/home/user/results/final_output.txt";
    Out = "stdout.log";
    Err = "stderr.log";
]
```

### Tarball Layout

The output tarball from the starter contains:

```
output.txt             (will be remapped)
results/data.json      (preserves directory structure)
stdout.log             (standard output)
stderr.log             (standard error)
```

### Filesystem Layout After Extraction

Based on the job ad, files should be placed as follows:

```
/home/user/results/
  final_output.txt     (remapped from output.txt)

/home/user/myproject/
  results/
    data.json          (written to Iwd/results/)
  stdout.log           (written to Iwd)
  stderr.log           (written to Iwd)
```

**Key Points:**
- Files in `TransferOutputRemaps` are written to their remapped destinations
- Other files are written relative to `Iwd`
- Directory structure within the tarball is preserved
- Remaps can specify absolute or relative paths (relative to `Iwd`)

### Wildcard Patterns

If `TransferOutput` contains wildcards:

```classad
[
    TransferOutput = "output_*.txt,results/*.json";
]
```

The extraction logic should:
1. Match all files in the tarball against the patterns
2. Extract only matching files
3. Apply remaps to matching files if applicable

### Default Output Files

If `TransferOutput` is not specified or empty, all files in the tarball are extracted to `Iwd`.

## Error Handling

### Input Sandbox Errors

- **Missing input file**: Return error if a file in `TransferInput` doesn't exist
- **Inaccessible `Iwd`**: Return error if `Iwd` directory is not readable
- **Missing executable**: Return error if `TransferExecutable = true` but `Cmd` file doesn't exist
- **Tar creation failure**: Return error if tar writer fails

### Output Sandbox Errors

- **Invalid tarball**: Return error if tar reader fails
- **Inaccessible `Iwd`**: Return error if `Iwd` directory is not writable
- **Remap destination error**: Return error if a remapped path cannot be written
- **Disk full**: Return error if filesystem runs out of space during extraction

## Integration with Existing Code

### Relationship to `schedd_transfer.go`

The sandbox API complements but differs from `schedd_transfer.go`:

- **`schedd_transfer.go`**: Implements the HTCondor wire protocol for transferring sandboxes between schedd and client
  - `ReceiveJobSandbox()`: Receives output files from schedd via CEDAR protocol
  - `SendJobSandbox()`: Sends input files to schedd via CEDAR protocol (if implemented)

- **`sandbox` package**: Implements filesystem-level sandbox operations
  - `CreateInputSandboxTar()`: Creates tarball from local files (no network)
  - `ExtractOutputSandbox()`: Extracts tarball to local filesystem (no network)

### Use Cases

**Use Case 1: Local Job Preparation**
```go
// Prepare input sandbox locally before submission
jobAd := createJobAd()
var buf bytes.Buffer
if err := sandbox.CreateInputSandboxTar(ctx, jobAd, &buf); err != nil {
    return err
}
// Now upload buf.Bytes() via HTTP API or other mechanism
```

**Use Case 2: Job Output Processing**
```go
// Process job output after retrieval
outputTar := downloadOutputSandbox(jobID)
jobAd := getJobAd(jobID)
if err := sandbox.ExtractOutputSandbox(ctx, jobAd, outputTar); err != nil {
    return err
}
// Files are now in their proper locations on the filesystem
```

**Use Case 3: Testing Job Execution**
```go
// In integration test:
// 1. Create input sandbox tarball
// 2. Submit job with input files
// 3. Compare running job's filesystem with tarball contents
// 4. After job completes, create tarball of output files
// 5. Verify output sandbox extraction places files correctly
```

## Implementation Notes

### Directory Creation

When extracting output files, the API should:
1. Create parent directories as needed (like `mkdir -p`)
2. Set appropriate permissions on created directories
3. Handle existing directories gracefully (don't fail if dir exists)

### Symbolic Links

For symbolic links in the sandbox:
- **Input sandbox**: Include symlinks as-is in the tarball (preserve link target)
- **Output sandbox**: Extract symlinks from the tarball (create the link)

### Large Files

The API should support streaming to handle large files efficiently:
- Don't read entire files into memory
- Stream directly from filesystem to tar writer
- Stream directly from tar reader to filesystem

### Permissions

- **Input sandbox**: Preserve source file permissions in tarball
- **Output sandbox**: Restore file permissions from tarball
- Use safe defaults (e.g., 0644 for files, 0755 for directories) if permissions are missing

## Testing Strategy

### Unit Tests

1. **Input sandbox creation**:
   - Test with simple file list
   - Test with subdirectories
   - Test with executable
   - Test with absolute paths
   - Test with missing files (should error)
   - Verify tarball contents and file modes

2. **Output sandbox extraction**:
   - Test with simple file list
   - Test with remaps
   - Test with subdirectories
   - Test with stdout/stderr files
   - Test with wildcard patterns
   - Verify filesystem layout after extraction

### Integration Tests

1. **Input sandbox roundtrip**:
   ```go
   // Submit job with input files
   // Job script: ls -laR > listing.txt
   // Verify job sees files matching input tarball layout
   ```

2. **Output sandbox roundtrip**:
   ```go
   // Submit job that creates output files
   // Job script: echo "result" > output.txt; mkdir results; echo "{}" > results/data.json
   // Download output sandbox
   // Verify extracted files match expected locations
   ```

3. **Remap verification**:
   ```go
   // Submit job with transfer_output_remaps
   // Verify files land in remapped locations after extraction
   ```

## Questions for HTCondor Developers

1. **Absolute path handling**: When a file in `TransferInput` has an absolute path outside `Iwd`, should the tarball:
   - Flatten it to the tarball root (e.g., `/tmp/file.txt` → `file.txt`)?
   - Preserve the full absolute path (e.g., `/tmp/file.txt` → `tmp/file.txt`)?
   - Fail with an error?

2. **Wildcard matching**: For `TransferOutput` wildcards, should the API:
   - Use glob patterns (like shell wildcards)?
   - Use regex patterns?
   - Support both?

3. **Missing output files**: If `TransferOutput` specifies a file that doesn't exist in the tarball:
   - Is this an error?
   - Should it be silently ignored?
   - Should it be logged as a warning?

4. **TransferOutput empty**: If `TransferOutput` is not set or empty:
   - Extract all files from tarball?
   - Extract nothing?
   - Use a default set of files?

5. **Security**: Are there any security considerations for:
   - Following symlinks during sandbox creation?
   - Extracting symlinks during sandbox extraction?
   - Handling files with setuid/setgid bits?

6. **Compression**: Should the tarball be compressed (gzip/bzip2)?
   - Or is compression handled at a different layer?

## References

- HTCondor Shadow implementation: `src/condor_shadow.V6.1/`
- HTCondor Starter implementation: `src/condor_starter.V6.1/`
- File transfer protocol: `src/condor_io/file_transfer.cpp`
- This project's transfer implementation: `schedd_transfer.go`, `file_transfer.go`
