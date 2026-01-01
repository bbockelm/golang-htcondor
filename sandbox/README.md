# Sandbox Package

The `sandbox` package provides utilities for creating and extracting HTCondor job sandboxes at the filesystem level.

## Overview

The sandbox package implements two complementary operations:

1. **Input Sandbox Creation**: Creates a tarball containing all input files specified in a job ad
2. **Output Sandbox Extraction**: Extracts output files from a tarball to their proper locations

These operations mimic the logic that the HTCondor shadow uses when interacting with the starter, but operate at the filesystem level without requiring network communication.

## API

### CreateInputSandboxTar

```go
func CreateInputSandboxTar(ctx context.Context, jobAd *classad.ClassAd, w io.Writer) error
```

Creates a tarball containing all input files specified in the job ad.

**Job Ad Attributes:**
- `Iwd`: Initial working directory (base path for relative files)
- `TransferInput`: Comma-separated list of input files
- `Cmd`: Executable path
- `TransferExecutable`: Whether to include the executable in the tarball

**Example:**

```go
import (
    "bytes"
    "context"
    "github.com/bbockelm/golang-htcondor/sandbox"
    "github.com/PelicanPlatform/classad/classad"
)

// Create job ad
jobAd := classad.New()
_ = jobAd.Set("Iwd", "/home/user/myproject")
_ = jobAd.Set("TransferInput", "input.txt,data/params.json")
_ = jobAd.Set("Cmd", "/home/user/myproject/script.sh")
_ = jobAd.Set("TransferExecutable", true)

// Create input sandbox tarball
var buf bytes.Buffer
err := sandbox.CreateInputSandboxTar(context.Background(), jobAd, &buf)
if err != nil {
    panic(err)
}

// buf now contains the tarball
```

### ExtractOutputSandbox

```go
func ExtractOutputSandbox(ctx context.Context, jobAd *classad.ClassAd, r io.Reader) error
```

Extracts files from an output sandbox tarball and places them in the appropriate locations.

**Job Ad Attributes:**
- `Iwd`: Initial working directory (default location for output files)
- `TransferOutput`: Comma-separated list of files to extract (empty = extract all)
- `TransferOutputRemaps`: Semicolon-separated `src=dest` remappings

**Example:**

```go
import (
    "context"
    "os"
    "github.com/bbockelm/golang-htcondor/sandbox"
    "github.com/PelicanPlatform/classad/classad"
)

// Create job ad
jobAd := classad.New()
_ = jobAd.Set("Iwd", "/home/user/myproject")
_ = jobAd.Set("TransferOutput", "output.txt,results/data.json")
_ = jobAd.Set("TransferOutputRemaps", "output.txt=/home/user/final/result.txt")

// Extract output sandbox
outputTar, _ := os.Open("output_sandbox.tar")
defer outputTar.Close()

err := sandbox.ExtractOutputSandbox(context.Background(), jobAd, outputTar)
if err != nil {
    panic(err)
}

// Files are now extracted to their proper locations
```

## Features

### Input Sandbox

- **Directory Structure Preservation**: Files in subdirectories maintain their relative paths in the tarball
- **Absolute Path Handling**: Absolute paths outside `Iwd` are flattened to the tarball root using their basename
- **Executable Transfer**: The executable is included if `TransferExecutable = true`
- **Permission Preservation**: File permissions are preserved in the tarball

### Output Sandbox

- **Selective Extraction**: Only files matching `TransferOutput` are extracted (wildcards supported)
- **Output Remapping**: Files can be remapped to different destinations via `TransferOutputRemaps`
- **Wildcard Support**: `TransferOutput` supports glob patterns (e.g., `output_*.txt`)
- **Extract All**: If `TransferOutput` is empty, all files in the tarball are extracted
- **Directory Creation**: Parent directories are created automatically as needed

## Use Cases

### 1. Job Preparation

Create an input sandbox locally before submitting a job:

```go
jobAd := createJobAd()
var inputTar bytes.Buffer
if err := sandbox.CreateInputSandboxTar(ctx, jobAd, &inputTar); err != nil {
    return err
}

// Upload inputTar via HTTP API or other mechanism
uploadJobInputs(jobID, inputTar.Bytes())
```

### 2. Output Processing

Process job output after retrieving the output sandbox:

```go
// Download output sandbox
outputTar := downloadOutputSandbox(jobID)
jobAd := getJobAd(jobID)

// Extract to filesystem
if err := sandbox.ExtractOutputSandbox(ctx, jobAd, outputTar); err != nil {
    return err
}

// Files are now in their proper locations
```

### 3. Testing

Verify job execution behavior in integration tests:

```go
// Submit job with input files
clusterID := submitJob(submitFile)
jobAd := getJobAd(clusterID)

// Create expected input sandbox
var expectedTar bytes.Buffer
sandbox.CreateInputSandboxTar(ctx, jobAd, &expectedTar)

// Compare running job's filesystem with tarball contents
verifyJobFilesystem(clusterID, expectedTar)
```

## Relationship to Other Packages

The sandbox package complements but differs from `schedd_transfer.go`:

| Package | Purpose | Network Required |
|---------|---------|------------------|
| `schedd_transfer.go` | Transfer sandboxes via HTCondor wire protocol | Yes |
| `sandbox` | Create/extract sandboxes at filesystem level | No |

**Workflow:**

1. **Job Submission**:
   - `sandbox.CreateInputSandboxTar()` → Create local tarball
   - `schedd.SpoolJobFiles()` → Upload tarball to schedd

2. **Job Completion**:
   - `schedd.ReceiveJobSandbox()` → Download tarball from schedd
   - `sandbox.ExtractOutputSandbox()` → Extract to filesystem

## Testing

### Unit Tests

Run unit tests with:

```bash
go test ./sandbox/
```

Unit tests cover:
- Simple file lists
- Subdirectories
- Absolute paths
- Missing files (error handling)
- Output remapping
- Wildcard matching
- Extract all behavior

### Integration Tests

Run integration tests with:

```bash
go test -tags=integration ./sandbox/
```

Integration tests verify:
- Input sandbox tarball matches running job's filesystem
- Output files are placed in correct locations after extraction
- Output remapping works correctly with real jobs

Integration tests require HTCondor to be installed.

## Design

See [design_notes/SANDBOX_API.md](../design_notes/SANDBOX_API.md) for detailed design documentation, including:
- Example job ads and tarball layouts
- Filesystem mapping examples
- Error handling strategies
- Questions for HTCondor developers

## Implementation Notes

### Absolute Paths

When a file in `TransferInput` has an absolute path outside `Iwd`:
- If the file is under `Iwd`, the relative path is used in the tarball
- Otherwise, only the basename is used (file is flattened to tarball root)

Example:
```
Iwd = /home/user/project
TransferInput = /tmp/external.txt,input.txt

Tarball contents:
  external.txt  (from /tmp/external.txt)
  input.txt     (from /home/user/project/input.txt)
```

### Wildcard Patterns

`TransferOutput` supports glob-style wildcards using Go's `filepath.Match()`:
- `*` matches any sequence of characters
- `?` matches any single character
- `[abc]` matches any character in the set

Example:
```
TransferOutput = output_*.txt,results/*.json
```

### Output Remaps

Remaps can specify absolute or relative paths:
- **Absolute**: File is written to that absolute path
- **Relative**: File is written relative to `Iwd`

Example:
```
Iwd = /home/user/project
TransferOutputRemaps = "output.txt=/var/results/final.txt;data.json=processed/data.json"

Result:
  output.txt → /var/results/final.txt (absolute)
  data.json → /home/user/project/processed/data.json (relative to Iwd)
```

## License

This package is part of golang-htcondor and is licensed under the Apache License 2.0.
