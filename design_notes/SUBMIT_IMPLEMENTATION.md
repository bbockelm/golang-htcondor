# Submit File to ClassAd Transformation - Implementation Status

This document describes the current implementation of job submit file parsing and transformation to HTCondor ClassAds in `submit.go`, based on the C++ reference implementation in `submit_utils.cpp.reference`.

## Known Issues & Limitations

### ~~Reserved Keywords in Submit Files~~ ✅ **FIXED**

~~HTCondor's config lexer treats certain words as reserved keywords that cannot be used as attribute names:~~
- ✅ **FIXED**: `error` and `warning` - The lexer now looks ahead to differentiate between assignment (`error = value`) and directive (`error: message`) forms
- `if`, `elif`, `else`, `endif` - Conditionals (still reserved, but not typically used as attribute names)
- `defined` - Conditional expression function (still reserved)

The parser now correctly handles:
```
# This works now:
error = error.txt
warning = warning.log

# This still works as a directive:
error: This is an error message
```

## Implemented Features

### Core Structure
- ✅ `SubmitFile` struct for parsing submit files
- ✅ `ParseSubmitFile()` - Parse submit file using config parser
- ✅ `MakeJobAd()` - Transform submit file to ClassAd
- ✅ Basic universe support (Standard, Vanilla, Grid, Java, Parallel, Local, VM, Docker)

### Job Attributes
- ✅ **Executable & Arguments**: `Cmd`, `Args`
- ✅ **Standard I/O**: `In`, `Out`, `Err`, `UserLog`
- ✅ **Environment**: `Environment` attribute
- ✅ **File Transfer**:
  - `ShouldTransferFiles`, `WhenToTransferOutput`
  - `TransferInput`, `TransferOutput` (comma-separated lists)
  - `TransferOutputRemaps` (semicolon-separated remaps)
  - `TransferExecutable`, `EncryptInputFiles`, `EncryptOutputFiles`
  - `DontEncryptInputFiles`, `DontEncryptOutputFiles`
  - `TransferPlugins`, `SkipFileChecks`, `PreserveRelativePaths`
- ✅ **Requirements**: Enhanced requirements generation with:
  - User-specified requirements
  - Automatic OpSys/Arch/Disk checks
  - Resource-based requirements (Memory, CPUs, GPUs)
  - Container support detection (Docker, Singularity, Apptainer)
  - File system domain matching
  - File transfer capability checks
- ✅ **Resource Requests**:
  - `RequestCpus`, `RequestMemory`, `RequestDisk` with defaults
  - `RequestGpus`, `RequestGpuMemory`
  - `RequireGpus` (GPU properties)
- ✅ **Container/Docker Support**:
  - `DockerImage`, `ContainerImage`
  - `DockerNetworkType`, `DockerVolumes`
  - `DockerPullPolicy`, `RequireContainer`
  - `ContainerTargetDir`, `ContainerServiceNames`
  - `DockerMountVolumes`, `MountUnderScratch`
  - `DockerOverrideEntrypoint`, `ContainerImageSHA256`
- ✅ **Job Status and Control**:
  - `JobStatus` (hold state), `HoldReason`, `HoldReasonCode`, `HoldReasonSubCode`
  - `JobPrio` (priority), `NiceUser`
  - `MaxJobRetirementTime`, `JobMaxVacateTime`
  - `MaxRetries`, `RetryUntil`, `SuccessExitCode`
  - `LeaveJobInQueue`, `KeepClaimIdle`, `JobLeaseDuration`
  - `ConcurrencyLimits`, `ConcurrencyLimitsExpr`
- ✅ **Custom Attributes**: Support for `+` and `MY.` prefixed attributes with type detection
- ✅ **Notification**: `EmailAttributes`, `NotifyUser`, `JobNotification`
- ✅ **Rank**: `Rank` expression
- ✅ **Ownership**: `Owner`, `AccountingGroup`, `AccountingGroupUser` (placeholder for Owner)
- ✅ **Job Identifiers**: `ClusterId`, `ProcId`, `JobUniverse`, `JobStatus`
- ✅ **Signal Handling**: `KillSig`, `RemoveKillSig`, `KillSigTimeout`
- ✅ **Simple Job Expressions**: Notification, streaming I/O, buffer configuration, batch names, remote directories
- ✅ **Extended Job Expressions**: File operations, duration limits, checkpointing, transfer limits, machine attribute tracking

### Job Submission
- ✅ `Submit()` method to create cluster and proc ads
- ✅ `SubmitLate()` method for late materialization submission
- ✅ `MakeClusterAd()` - Create cluster ad template
- ✅ `MakeProcAd()` - Create proc-specific ad with variables
- ✅ `SubmitResult` struct for submission results
- ✅ `Keys()` method on Config for iterating over all submit file attributes
- ✅ **Late Materialization**: Efficient template-based job creation for large submissions
- ✅ **Macro Expansion**: Full support for HTCondor submit-time macros ($(Cluster), $(Process), $(ItemIndex), etc.)

### Parser/Lexer Enhancements
- ✅ **Queue Statement Parsing**: Full support for all queue statement forms:
  - `queue` - Simple queue with default count of 1
  - `queue N` - Queue N jobs
  - `queue var1, var2 from file` - Queue from file with variable assignment
  - `queue N var1, var2 from file` - Queue N items from file
  - `queue var in (item1, item2, item3)` - Queue from inline list
  - `queue N var in (item1, item2)` - Queue N items from inline list
  - `queue matching pattern` - Queue matching files (pattern in File field)
  - `queue N matching pattern` - Queue N matching files
- ✅ **Queue Statement Execution**: Iterators for generating multiple job ads:
  - Simple iterator for `queue [N]`
  - List iterator for `queue in (...)` forms
  - File iterator for `queue from file` forms
  - Matching iterator for `queue matching pattern` forms
  - Variable substitution in job attributes
  - Multiple job ad generation with sequential ProcIds
- ✅ **Error/Warning Keyword Fix**: Lexer now correctly differentiates between:
  - `error = filename.txt` (assignment)
  - `error: error message` (directive)
  - Uses lookahead to check for `=` vs `:` after the keyword

## Not Yet Implemented (TODO)

### 1. ~~Queue Statement Parsing~~ ✅ **COMPLETED**
~~**Priority: HIGH**~~
- ✅ Queue count parsing (`queue 10`)
- ✅ Queue with variables (`queue foo from list`)
- ✅ Queue with iteration (`queue in (a, b, c)`)
- ⚠️ Queue slicing (`queue 10 from itemlist[1:5]`) - Not yet implemented
- ✅ Multi-variable queue statements
- ✅ Parser updated with QUEUE, FROM, IN, MATCHING tokens
- ✅ Grammar rules added for all queue forms
- ✅ **Queue statement execution/iteration logic implemented**
  - ✅ Iterator pattern for different queue forms
  - ✅ Variable substitution during job ad creation
  - ✅ Multiple job ad generation
  - ✅ Support for all queue forms (simple, from file, in list, matching)
  - ✅ Comprehensive test coverage (11 tests)

### 2. ~~Grid Universe Parameters~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ Grid type and resource configuration
- ✅ Grid-specific attributes:
  - ✅ EC2: `ec2_ami_id`, `ec2_instance_type`, `ec2_keypair`, `ec2_keypair_file`, `ec2_access_key_id`, `ec2_secret_access_key`, `ec2_security_groups`, `ec2_security_ids`, `ec2_availability_zone`, `ec2_ebs_volumes`, `ec2_elastic_ip`, `ec2_iam_profile_arn`, `ec2_iam_profile_name`, `ec2_spot_price`, `ec2_user_data`, `ec2_user_data_file`
  - ✅ GCE: `gce_image`, `gce_machine_type`, `gce_metadata`, `gce_metadata_file`, `gce_account`, `gce_auth_file`
  - ✅ Azure: `azure_image`, `azure_location`, `azure_size`, `azure_admin_username`, `azure_admin_key`, `azure_auth_file`
  - ✅ Batch systems: `batch_queue`, `batch_project`, `batch_runtime`, `batch_resources`
  - ✅ ARC: `arc_rte`, `arc_resources`
- ✅ Credential delegation: `delegate_job_gsi_credentials_lifetime`
- ✅ Comprehensive test coverage

**C++ Reference**: `SetGridParams()` (called in `make_job_ad`)

### 3. ~~VM Universe Parameters~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ VM type (KVM, Xen, VMware): `vm_type`
- ✅ VM memory, disk, networking: `vm_memory`, `vm_disk`, `vm_networking`, `vm_networking_type`, `vm_macaddr`
- ✅ VCPUS configuration: `vm_vcpus`
- ✅ Checkpoint: `vm_checkpoint`
- ✅ Xen-specific: `xen_kernel`, `xen_initrd`, `xen_root`, `xen_kernel_params`
- ✅ VMware-specific: `vmware_dir`, `vmware_snapshot_disk`, `vmware_should_transfer_files`
- ✅ Comprehensive test coverage

**C++ Reference**: `SetVMParams()` (called in `make_job_ad`)

### 4. ~~Parallel/MPI Universe Parameters~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ Machine count: `machine_count`
- ✅ Test coverage for MPI jobs

**C++ Reference**: `SetParallelParams()` (called in `make_job_ad`)

### 5. ~~Java Universe Parameters~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ JAR files: `jar_files`
- ✅ JVM arguments: `java_vm_args`
- ✅ Test coverage

**C++ Reference**: `SetJavaVMArgs()` (called in `make_job_ad`)

### 6. ~~Docker/Container Support~~ ✅ **COMPLETED**
~~Priority: HIGH (Docker is commonly used)~~
- ✅ Container image specification
- ✅ Container universe (deprecated, but still used)
- ✅ Container network settings
- ✅ Volume mounts

### 7. ~~File Transfer Details~~ ✅ **COMPLETED**
~~Priority: HIGH~~
- ✅ `transfer_input_files` parsing (comma-separated list)
- ✅ `transfer_output_files` parsing
- ✅ `transfer_output_remaps`
- ✅ File transfer encryption (encrypt/dont_encrypt)
- ✅ Plugin support
- ✅ Skip file checks and preserve relative paths
- ⚠️ URL-based file transfer (not yet implemented)
- ⚠️ Protected URL mapping (not yet implemented)
- ⚠️ Per-file checksums (not yet implemented)

### 8. ~~Advanced Requirements~~ ✅ **COMPLETED**
~~Priority: HIGH~~
- ✅ Automatic requirements generation based on resources
- ✅ Machine matching optimization
- ✅ Target type requirements
- ✅ Request vs actual resource relationship
- ✅ Container capability detection
- ✅ GPU requirements

### 9. ~~Job Status and Control~~ ✅ **COMPLETED**
~~Priority: MEDIUM~~
- ✅ Initial hold reasons (`hold`, `hold_reason`)
- ✅ Job priority
- ✅ Nice user flag
- ✅ Job max vacate time
- ✅ Job retries and retry delays
- ✅ Concurrency limits

### 10. ~~Periodic Expressions~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ Periodic hold expressions: `periodic_hold`, `periodic_hold_reason`, `periodic_hold_subcode`
- ✅ Periodic remove expressions: `periodic_remove`, `periodic_remove_reason`
- ✅ Periodic release expressions: `periodic_release`, `periodic_release_reason`
- ✅ On-exit expressions: `on_exit_hold`, `on_exit_hold_reason`, `on_exit_hold_subcode`, `on_exit_remove`, `on_exit_remove_reason`
- ✅ Cron-style job scheduling: `cron_minute`, `cron_hour`, `cron_day_of_month`, `cron_month`, `cron_day_of_week`, `cron_prep_time`, `cron_window`
- ✅ Job deferral: `deferral_time`, `deferral_window`, `deferral_prep_time`
- ✅ Comprehensive test coverage

**C++ Reference**: `SetPeriodicExpressions()`, `SetJobDeferral()` (called in `make_job_ad`)

### 12. ~~Signal Handling~~ ✅ **COMPLETED**
~~**Priority: LOW**~~
- ✅ Kill signal specification: `kill_sig` (string or integer)
- ✅ Remove signal specification: `remove_kill_sig` (string or integer)
- ✅ Kill signal timeout: `kill_sig_timeout`
- ✅ Comprehensive test coverage

**C++ Reference**: `SetKillSig()` (called in `make_job_ad`)

### 13. ~~Concurrency Limits~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ Concurrency limits attribute: `concurrency_limits`
- ✅ Concurrency limits expression: `concurrency_limits_expr`
- ✅ Already implemented in `setJobStatusControl()`

**C++ Reference**: `SetConcurrencyLimits()` (called in `make_job_ad`)

### 14. OAuth/Credentials
**Priority: MEDIUM**
- OAuth service names
- Credential handling
- SciToken support

**C++ Reference**: `SetOAuth()`, `SetGSICredentials()` (called in `make_job_ad`)

### 15. ~~Custom Attributes~~ ✅ **COMPLETED**
~~**Priority: HIGH**~~
- ✅ `+AttributeName` syntax (job ClassAd attributes)
- ✅ `MY.AttributeName` syntax (same as +)
- ✅ Attribute validation and type detection
- ✅ Expression vs string detection (boolean, integer, float, string)
- ✅ Already implemented in `setCustomAttributes()`

**C++ Reference**: `SetForcedSubmitAttrs()`, `SetForcedAttributes()` (lines 8268-8274 in `make_job_ad`)

### 16. ~~Simple and Extended Job Expressions~~ ✅ **COMPLETED**
~~**Priority: MEDIUM**~~
- ✅ **Simple Job Expressions** (`setSimpleJobExprs()`):
  - ✅ Image and executable size attributes
  - ✅ Disk usage tracking
  - ✅ Remote initial directory
  - ✅ Job notification (always, complete, error, never)
  - ✅ Remote I/O and syscalls
  - ✅ Streaming I/O (stdin, stdout, stderr)
  - ✅ Job description
  - ✅ Copy to spool
  - ✅ I/O buffer configuration
  - ✅ Batch name and stack size
- ✅ **Extended Job Expressions** (`setExtendedJobExprs()`):
  - ✅ File operations (append, compress, fetch, local, remaps)
  - ✅ Graceful removal
  - ✅ Run as owner and load profile
  - ✅ Job ad information attributes
  - ✅ I/O proxy
  - ✅ Machine attribute tracking and history
  - ✅ EC2 tags
  - ✅ Duration limits (execute and total job)
  - ✅ Checkpoint configuration
  - ✅ Transfer size limits
  - ✅ Java keystore parameters
  - ✅ MPI remote node number
- ✅ Comprehensive test coverage (15+ tests)

**C++ Reference**: `SetSimpleJobExprs()`, `SetExtendedJobExprs()` (called in `make_job_ad`)

### 17. ~~Auto-Generated Attributes~~ ✅ **COMPLETED**
~~**Priority: HIGH**~~
- ✅ Automatic attribute population based on other settings:
  - ✅ `Iwd` - Initial working directory from `initialdir`
  - ✅ `Owner` - Job owner from configuration
  - ✅ `NumJobStarts` - Job start counter (initialized to 0)
  - ✅ `NumRestarts` - Restart counter (initialized to 0)
  - ✅ `NumSystemHolds` - System hold counter (initialized to 0)
  - ✅ `JobRunCount` - Run count (initialized to 0)
- ✅ Comprehensive test coverage

**C++ Reference**: `SetAutoAttributes()`, `SetImageSize()`, `SetIWD()` (called in `make_job_ad`)

### 18. Jobset Support
**Priority: LOW**
- Jobset membership
- Jobset attributes

**C++ Reference**: `ProcessJobsetAttributes()` (called in `make_job_ad`)

### 19. TDP (Token Distribution Protocol)
**Priority: LOW**
- TDP configuration for file transfer

**C++ Reference**: `SetTDP()` (called in `make_job_ad`)

### 20. Mistake Detection and Warnings
**Priority: MEDIUM**
- Common mistake detection
- Helpful error messages
- Submit file validation

**C++ Reference**: `ReportCommonMistakes()` (called in `make_job_ad`)

### 21. ~~Late Materialization Support~~ ✅ **COMPLETED**
~~**Priority: HIGH** (This is how the Schedd actually processes queue statements)~~
- ✅ Cluster ad vs proc ad separation:
  - ✅ `MakeClusterAd()` - Creates cluster ad template
  - ✅ `MakeProcAd()` - Creates proc-specific ad with queue variables
  - ✅ `SubmitLate()` - Efficient submission using late materialization pattern
- ✅ Template-based job creation:
  - ✅ Cluster ad serves as template with common attributes
  - ✅ Proc ads contain only per-job differing attributes
  - ✅ Reduces memory and network overhead for large submissions
- ✅ Variable substitution in queue statements:
  - ✅ Proper handling of queue variables in late materialization
  - ✅ Macro context management per-job
- ✅ Iterator handling integrated with late materialization
- ✅ Comprehensive test coverage (10+ tests)

**C++ Reference**: Multiple references throughout, `clusterAd` handling, `base_job_is_cluster_ad` logic

### 22. ~~Macro Expansion in Submit Context~~ ✅ **COMPLETED**
~~**Priority: HIGH**~~
- ✅ Submit-specific macro expansion:
  - ✅ `$(Cluster)` / `$(ClusterId)` - Cluster ID
  - ✅ `$(Process)` / `$(ProcId)` - Process/Proc ID
  - ✅ `$(Node)` - Alias for Process (parallel universe)
  - ✅ `$(Step)` - Step counter for queue iteration
  - ✅ `$(Row)` - Row counter for queue iteration
  - ✅ `$(Item)` / `$(ItemIndex)` - Item index in queue iteration
  - ✅ Queue variable macros (e.g., `$(inputfile)` from `queue inputfile in ...`)
- ✅ Live macro values during iteration:
  - ✅ `pushMacroContext()` - Sets up per-job macro values
  - ✅ `popMacroContext()` - Cleans up after job ad creation
  - ✅ Proper macro scope management for each proc
- ✅ Integration with config package's existing macro expansion
- ✅ `expandSubmitMacros()` helper for explicit expansion
- ✅ Comprehensive test coverage (15+ tests)

**C++ Reference**: `LiveClusterString`, `LiveProcessString`, etc. (lines 8173-8176), various macro expansion methods

### 23. File Checking and Validation
**Priority: HIGH**
- File existence checks
- File permission validation
- Executable verification
- Transfer file validation

**C++ Reference**: `FnCheckFile` callback, `check_open()` methods

### 24. DAG Command Recognition
**Priority: LOW** (Only needed for DAGMan integration)
- Recognize DAG-specific commands to avoid conflicts

**C++ Reference**: `is_dag_command()` (line 8357)

## Architecture Differences from C++ Implementation

### Current Go Implementation
1. **Parser**: Reuses the existing `config` package parser
   - Pro: Consistency, already handles HTCondor config syntax
   - Con: Doesn't handle queue statements yet

2. **Structure**: Simpler object model
   - `SubmitFile` wraps a `Config` object
   - Direct ClassAd creation in `MakeJobAd()`
   - No macro set management

3. **Validation**: Minimal
   - Basic required field checking
   - No file existence validation
   - No common mistake detection

### C++ Implementation Structure
1. **Parser**: Integrated macro system with submit-specific features
2. **SubmitHash**: Complex state machine with:
   - Macro sets and live macro values
   - File checking callbacks
   - Cluster/proc ad management
   - Template/materialization support
3. **Validation**: Extensive error checking and warnings

## Implementation Recommendations

### Phase 1 (Foundation) - Completed ✅
- Basic submit file parsing
- Core attribute setting
- Simple job ad creation

### Phase 2 (Essential Features) - TODO
1. **Queue statement parsing** - Add to parser/lexer
2. **Custom attributes** - `+` and `MY.` prefix handling
3. **File transfer lists** - Parse comma-separated file lists
4. **Container support** - Docker/Apptainer image specification
5. **Macro expansion** - Submit-specific macros like $(Process)

### Phase 3 (Common Use Cases) - TODO
1. **Requirements generation** - Smarter automatic requirements
2. **Resource matching** - Better request_* handling
3. **File validation** - Check file existence and permissions
4. **Late materialization** - Template-based job creation

### Phase 4 (Advanced Features) - TODO
1. **Grid universe** - Full grid job support
2. **Parallel/MPI** - Multi-node jobs
3. **VM universe** - Virtual machine jobs
4. **Advanced expressions** - Periodic expressions, etc.

## Testing Needs

- Unit tests for basic transformation
- Integration tests with sample submit files
- Validation against C++ HTCondor's output
- Edge case handling (missing fields, invalid values, etc.)

## References

- C++ Implementation: `submit_utils.cpp.reference` (main reference file)
- HTCondor Documentation: https://htcondor.readthedocs.io/
- ClassAd Library: `github.com/PelicanPlatform/classad`
- Config Parser: `github.com/bbockelm/golang-htcondor/config`
