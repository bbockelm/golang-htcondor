package htcondor

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/filetransfer"
)

// ftOpts is the shared file-transfer wire configuration for the tool-side
// spool/receive paths. Logging is routed to the standard logger to preserve the
// long-standing per-file log output.
var ftOpts = filetransfer.Options{Logf: log.Printf}

// procID represents a job ID (cluster.proc)
type procID struct {
	cluster int32
	proc    int32
}

// ReceiveJobSandbox downloads job output files (sandbox) from the schedd for jobs matching the constraint.
// The files are written to a tar archive via the provided writer.
// This method starts the transfer in a goroutine and returns immediately.
// The caller should read from the returned channel to get the final result.
//
// Protocol (based on DCSchedd::receiveJobSandbox in reference/dc_schedd.cpp):
//  1. Connect to schedd and send TRANSFER_DATA_WITH_PERMS command
//  2. Perform DC_AUTHENTICATE handshake
//  3. Send version string (CondorVersion())
//  4. Send constraint expression
//  5. EOM
//  6. Receive number of matching jobs (int)
//  7. EOM
//  8. For each job:
//     a. Receive job ClassAd
//     b. EOM
//     c. Initialize FileTransfer with job ad
//     d. Call FileTransfer.DownloadFiles() to receive files
//     e. Files are sent using HTCondor's file transfer protocol
//  9. Send OK reply (int = 0)
//  10. EOM
//
// constraint: ClassAd constraint expression to select jobs (e.g., "ClusterId == 123")
// w: Writer where the tar archive will be written
// Returns: A channel that will receive the error result (nil on success)
func (s *Schedd) ReceiveJobSandbox(ctx context.Context, constraint string, w io.Writer) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		defer close(errChan)
		err := s.doReceiveJobSandbox(ctx, constraint, w)
		errChan <- err
	}()

	return errChan
}

// doReceiveJobSandbox implements the actual transfer logic
func (s *Schedd) doReceiveJobSandbox(ctx context.Context, constraint string, w io.Writer) error {
	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.TRANSFER_DATA_WITH_PERMS, "CLIENT", s.address)
	if err != nil {
		return fmt.Errorf("failed to create security config: %w", err)
	}

	// Connect to schedd and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 3. Send version string
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutString(ctx, "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $"); err != nil {
		return fmt.Errorf("failed to send version string: %w", err)
	}

	// 4. Send constraint expression
	if err := msg.PutString(ctx, constraint); err != nil {
		return fmt.Errorf("failed to send constraint: %w", err)
	}

	// 5. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish initial message: %w", err)
	}

	// 6. Receive number of matching jobs
	responseMsg := message.NewMessageFromStream(cedarStream)
	jobCount, err := responseMsg.GetInt32(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive job count: %w", err)
	}

	// 7. EOM (implicit)

	// Create tar writer
	tarWriter := tar.NewWriter(w)
	defer func() {
		if cerr := tarWriter.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close tar writer: %w", cerr)
		}
	}()

	// 8. For each job, receive job ad and files
	for i := int32(0); i < jobCount; i++ {
		if err := s.processJobSandbox(ctx, cedarStream, tarWriter, jobCount, i); err != nil {
			return err
		}
	}

	// 9. Send OK reply
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, 0); err != nil { // 0 = OK
		return fmt.Errorf("failed to send OK reply: %w", err)
	}

	// 10. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish OK reply: %w", err)
	}

	return nil
}

// processJobSandbox handles the reception of a single job's sandbox
func (s *Schedd) processJobSandbox(ctx context.Context, cedarStream *stream.Stream, tarWriter *tar.Writer, jobCount int32, i int32) error {
	// a. Receive job ClassAd
	responseMsg := message.NewMessageFromStream(cedarStream)
	jobAd, err := responseMsg.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive job ad %d: %w", i, err)
	}

	// b. EOM (implicit)

	// Get cluster.proc for directory prefix
	clusterExpr, ok := jobAd.Lookup("ClusterId")
	if !ok {
		return fmt.Errorf("job ad %d missing ClusterId", i)
	}
	clusterVal := clusterExpr.Eval(nil)
	clusterID, err := clusterVal.IntValue()
	if err != nil {
		return fmt.Errorf("job ad %d: ClusterId not an integer: %w", i, err)
	}

	procExpr, ok := jobAd.Lookup("ProcId")
	if !ok {
		return fmt.Errorf("job ad %d missing ProcId", i)
	}
	procVal := procExpr.Eval(nil)
	procID, err := procVal.IntValue()
	if err != nil {
		return fmt.Errorf("job ad %d: ProcId not an integer: %w", i, err)
	}

	dirPrefix := fmt.Sprintf("%d.%d", clusterID, procID)
	if jobCount == 1 {
		dirPrefix = ""
	}

	// Get list of transfer output files (if specified)
	var transferOutputFiles map[string]bool
	// Check TransferOutput (standard) and TransferOutputFiles (legacy/internal)
	lookupAttr := "TransferOutput"
	expr, ok := jobAd.Lookup(lookupAttr)
	if !ok {
		lookupAttr = "TransferOutputFiles"
		expr, ok = jobAd.Lookup(lookupAttr)
	}

	if ok {
		val := expr.Eval(nil)
		if str, err := val.StringValue(); err == nil && str != "" {
			fileList := parseFileList(str)
			transferOutputFiles = make(map[string]bool)
			for _, f := range fileList {
				transferOutputFiles[f] = true
			}
		}
	}

	// Also add Stdout and Stderr files if they exist and we are filtering
	if transferOutputFiles != nil {
		// Add standard output file
		if outExpr, ok := jobAd.Lookup("Out"); ok {
			val := outExpr.Eval(nil)
			if str, err := val.StringValue(); err == nil && str != "" && str != "/dev/null" {
				transferOutputFiles[str] = true
			}
		}

		// Add standard error file
		if errExpr, ok := jobAd.Lookup("Err"); ok {
			val := errExpr.Eval(nil)
			if str, err := val.StringValue(); err == nil && str != "" && str != "/dev/null" {
				transferOutputFiles[str] = true
			}
		}
	}

	// Parse TransferOutputRemaps for output file renaming
	var outputRemaps map[string]OutputRemap

	// Try to get TransferOutputRemaps - may be stored as SUBMIT_TransferOutputRemaps
	var remapsStr string
	for _, attrName := range []string{"TransferOutputRemaps", "SUBMIT_TransferOutputRemaps"} {
		if remapsExpr, ok := jobAd.Lookup(attrName); ok {
			val := remapsExpr.Eval(nil)
			if str, err := val.StringValue(); err == nil && str != "" {
				remapsStr = str
				// Strip outer quotes if present (ClassAd string handling artifact)
				// HTCondor stores string values with quotes as part of the value when using SUBMIT_* prefixed attrs
				remapsStr = strings.Trim(remapsStr, "\"")
				break
			}
		}
	}

	if remapsStr != "" {
		remapsList := parseOutputRemaps(remapsStr)
		outputRemaps = buildRemapLookup(remapsList)
	}

	// c-e. Receive files using the shared FileTransfer stream core, which reads
	// the preamble (final_transfer flag + xfer_info ad) and then the per-file
	// loop, writing to a tar-backed sink that applies the output-file filter and
	// remaps. The tool download path performs no final TransferAck (ReceiveAck
	// left false), preserving its long-standing behavior against the schedd.
	if err := s.receiveJobFiles(ctx, cedarStream, tarWriter, dirPrefix, transferOutputFiles, outputRemaps); err != nil {
		return fmt.Errorf("failed to receive files for job %d.%d: %w", clusterID, procID, err)
	}

	return nil
}

// receiveJobFiles receives files for a single job and writes them to the tar
// archive, delegating the wire protocol to filetransfer.ReceiveStream and
// applying the output-file filter, path-traversal guard and output remaps in a
// tar-backed Sink. ReceiveAck is left false to preserve the tool's behavior
// against the schedd's TRANSFER_DATA uploader (which sends no final ack here).
func (s *Schedd) receiveJobFiles(ctx context.Context, cedarStream *stream.Stream, tarWriter *tar.Writer, dirPrefix string, transferOutputFiles map[string]bool, outputRemaps map[string]OutputRemap) error {
	sink := &tarSink{
		tw:        tarWriter,
		dirPrefix: dirPrefix,
		filter:    transferOutputFiles,
		remaps:    outputRemaps,
	}
	_, err := filetransfer.ReceiveStream(ctx, cedarStream, sink, ftOpts)
	return err
}

// tarSink is a filetransfer.Sink that writes received files into a tar archive,
// preserving the download-path semantics of the former inline receive loop: an
// optional output-file allow-list, a path-traversal guard, and TransferOutput
// remaps (URL remaps are skipped since those files were transferred elsewhere).
type tarSink struct {
	tw        *tar.Writer
	dirPrefix string
	filter    map[string]bool        // nil => accept all
	remaps    map[string]OutputRemap // nil => no remaps
}

// tarEntryWriter adapts a tar entry to an io.WriteCloser; Close is a no-op since
// the next WriteHeader (or the tar.Writer's own Close) finalizes the entry.
type tarEntryWriter struct{ tw *tar.Writer }

func (w tarEntryWriter) Write(p []byte) (int, error) { return w.tw.Write(p) }
func (w tarEntryWriter) Close() error                { return nil }

func (t *tarSink) File(name string, mode int64, size int64) (io.WriteCloser, error) {
	if t.filter != nil && !t.filter[name] {
		log.Printf("Skipped file %s (not in TransferOutputFiles)", name)
		return nil, nil
	}
	cleanPath := path.Clean(name)
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/../") {
		log.Printf("Ignoring file with path traversal: %s", name)
		return nil, nil
	}
	outputPath := cleanPath
	if t.remaps != nil {
		if remappedPath, remap, found := applyOutputRemap(name, t.remaps); found {
			if remap.IsURL {
				log.Printf("Skipping file %s (remapped to URL: %s)", name, remap.Destination)
				return nil, nil
			}
			outputPath = remappedPath
			log.Printf("Remapping output file %s -> %s", name, outputPath)
		}
	}
	tarPath := path.Join(t.dirPrefix, outputPath)
	header := &tar.Header{Name: tarPath, Size: size, Mode: mode, ModTime: time.Now()}
	if err := t.tw.WriteHeader(header); err != nil {
		return nil, fmt.Errorf("failed to write tar header for %s: %w", tarPath, err)
	}
	return tarEntryWriter{tw: t.tw}, nil
}

func (t *tarSink) Mkdir(name string) error {
	cleanPath := path.Clean(name)
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/../") {
		log.Printf("Ignoring directory with path traversal: %s", name)
		return nil
	}
	tarPath := path.Join(t.dirPrefix, cleanPath)
	header := &tar.Header{Name: tarPath + "/", Mode: 0755, Typeflag: tar.TypeDir}
	if err := t.tw.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header for directory %s: %w", tarPath, err)
	}
	return nil
}

// SpoolJobFilesFromFS uploads input files to the schedd for the specified jobs.
// Files are read from the provided filesystem.
//
// The input files to transfer are determined from each job ad's TransferInput attribute.
// If TransferInput is not present, an error is returned.
//
// Protocol (based on DCSchedd::spoolJobFiles in reference/dc_schedd.cpp):
//  1. Connect to schedd and send SPOOL_JOB_FILES_WITH_PERMS command
//  2. Perform DC_AUTHENTICATE handshake
//  3. Send version string (CondorVersion())
//  4. Send number of jobs (int)
//  5. EOM
//  6. For each job, send PROC_ID structure (cluster, proc)
//  7. EOM
//  8. For each job:
//     a. Initialize FileTransfer with job ad
//     b. Call FileTransfer.UploadFiles() to send files
//     c. Files are sent using HTCondor's file transfer protocol
//  9. EOM
//  10. Receive reply (int, 1 = success, 0 = failure)
//  11. EOM
//
// jobAds: Array of job ClassAds containing ClusterId, ProcId, and TransferInput
// fsys: Filesystem containing the files to upload
// Returns: error if the upload fails
func (s *Schedd) SpoolJobFilesFromFS(ctx context.Context, jobAds []*classad.ClassAd, fsys fs.FS) error {
	if len(jobAds) == 0 {
		return fmt.Errorf("no job ads provided")
	}

	// Extract job IDs and file lists, and validate
	jobIDs := make([]procID, len(jobAds))
	fileLists := make([][]string, len(jobAds))

	for i, ad := range jobAds {
		// Get ClusterId
		clusterExpr, ok := ad.Lookup("ClusterId")
		if !ok {
			return fmt.Errorf("job ad %d missing ClusterId attribute", i)
		}
		clusterVal := clusterExpr.Eval(nil)
		clusterInt, err := clusterVal.IntValue()
		if err != nil {
			return fmt.Errorf("job ad %d: ClusterId is not an integer: %w", i, err)
		}

		// Get ProcId
		procExpr, ok := ad.Lookup("ProcId")
		if !ok {
			return fmt.Errorf("job ad %d missing ProcId attribute", i)
		}
		procVal := procExpr.Eval(nil)
		procInt, err := procVal.IntValue()
		if err != nil {
			return fmt.Errorf("job ad %d: ProcId is not an integer: %w", i, err)
		}

		//nolint:gosec // ClusterId and ProcId are bounded by HTCondor to int32 range
		jobIDs[i] = procID{cluster: int32(clusterInt), proc: int32(procInt)}

		// Build the per-job file list. Reuse the same logic as the Tar
		// spool path: TransferInput supplies the explicit inputs, and
		// the executable's basename is added when transfer_executable is
		// true (the default). This lets minimal jobs — those whose only
		// transferable file is the executable itself — spool successfully.
		fileSet := getInputFilesFromJobAd(ad)
		if len(fileSet) == 0 {
			return fmt.Errorf("job ad %d (job %d.%d): no files to spool (TransferInput is empty and TransferExecutable is false or Cmd is unset)", i, clusterInt, procInt)
		}
		fileLists[i] = make([]string, 0, len(fileSet))
		for f := range fileSet {
			fileLists[i] = append(fileLists[i], f)
		}
		// Sort so the wire order is deterministic across goroutine /
		// map-iteration randomness — easier to reason about in logs and
		// tests.
		sort.Strings(fileLists[i])
	}

	// Prepare security config — pull from context so an HTTP-handler
	// caller's bearer/JWT (set via WithSecurityConfig) is reused, not
	// silently dropped. Sibling paths (NewQmgmtConnection, the receive
	// path at the top of this file) do the same; spooling without it
	// makes the schedd reject the auth handshake with "no compatible
	// tokens available".
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.SPOOL_JOB_FILES_WITH_PERMS, "CLIENT", s.address)
	if err != nil {
		return fmt.Errorf("failed to build security config: %w", err)
	}

	// Connect to schedd and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 3. Send version string
	msg := message.NewMessageForStream(cedarStream)
	// Use a fixed version string for now; in real usage this would be CondorVersion()
	if err := msg.PutString(ctx, "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $"); err != nil {
		return fmt.Errorf("failed to send version string: %w", err)
	}

	// 4. Send number of jobs
	//nolint:gosec // len is bounded by memory, safe to convert to int32
	if err := msg.PutInt32(ctx, int32(len(jobAds))); err != nil {
		return fmt.Errorf("failed to send job count: %w", err)
	}

	// 5. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish initial message: %w", err)
	}

	// 6. Send PROC_ID structures for each job
	msg = message.NewMessageForStream(cedarStream)
	for i, id := range jobIDs {
		if err := msg.PutInt32(ctx, id.cluster); err != nil {
			return fmt.Errorf("failed to send cluster ID for job %d: %w", i, err)
		}
		if err := msg.PutInt32(ctx, id.proc); err != nil {
			return fmt.Errorf("failed to send proc ID for job %d: %w", i, err)
		}
	}

	// 7. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish job IDs message: %w", err)
	}

	// 8. For each job, send files using file transfer protocol
	for i, ad := range jobAds {
		if err := s.sendJobFiles(ctx, cedarStream, ad, fsys, fileLists[i], jobIDs[i]); err != nil {
			return fmt.Errorf("failed to send files for job %d.%d: %w", jobIDs[i].cluster, jobIDs[i].proc, err)
		}
	}

	return nil
}

// sendSingleFile sends a single file using the HTCondor file transfer protocol.
// It is a thin adapter over filetransfer.SendFile (the shared stream core):
// fileReader supplies the bytes, and peerGoesAheadAlways/fileIndex are bridged
// into a filetransfer.SendState so the GO_AHEAD_ALWAYS latch carries across a
// job's files exactly as before.
func (s *Schedd) sendSingleFile(ctx context.Context, cedarStream *stream.Stream, fileName string, fileSize int64, fileMode int64, fileReader io.Reader, peerGoesAheadAlways *bool, fileIndex int) error {
	state := &filetransfer.SendState{PeerGoesAheadAlways: *peerGoesAheadAlways, FileIndex: fileIndex}
	spec := filetransfer.FileSpec{
		WireName: fileName,
		Mode:     fileMode,
		Size:     fileSize,
		Open:     func() (io.ReadCloser, error) { return io.NopCloser(fileReader), nil },
	}
	err := filetransfer.SendFile(ctx, cedarStream, spec, state, ftOpts)
	*peerGoesAheadAlways = state.PeerGoesAheadAlways
	return err
}

// sendJobFiles sends files for a single job using the HTCondor file transfer protocol
// This implements the file sending portion based on FileTransfer::DoUpload from file_transfer.cpp
//
// Protocol (per FileTransfer::DoUpload):
// 1. Send final_transfer flag (int) - 0 for intermediate, 1 for final
// 2. If peer version >= 8.1.0, send xfer_info ClassAd with ATTR_SANDBOX_SIZE
// 3. EOM
// 4. For each file: send CommandXferFile, filename, file data
// 5. Send CommandFinished
func (s *Schedd) sendJobFiles(ctx context.Context, cedarStream *stream.Stream, _ *classad.ClassAd, fsys fs.FS, fileList []string, _ procID) error {
	// Use provided file list
	inputFiles := fileList

	log.Printf("sendJobFiles: received %d input files to send", len(inputFiles))

	// Build the send plan (intermediate/spool transfer). Each file is opened
	// lazily against fsys as filetransfer.SendStream streams it.
	plan := filetransfer.SendPlan{FinalTransfer: false}
	for _, filePath := range inputFiles {
		info, err := fs.Stat(fsys, filePath)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", filePath, err)
		}
		name := filePath
		plan.Files = append(plan.Files, filetransfer.FileSpec{
			WireName: name,
			Mode:     int64(info.Mode().Perm()),
			Size:     info.Size(),
			Open:     func() (io.ReadCloser, error) { return fsys.Open(name) },
		})
	}

	return filetransfer.SendStream(ctx, cedarStream, plan, ftOpts)
}

// SpoolJobFilesFromTar uploads input files to the schedd for the specified jobs.
// Files are read from a tar archive.
//
// Protocol: Same as SpoolJobFilesFromFS
//
// The tar archive should be organized as:
//   - For single job: files directly at root (no cluster.proc prefix)
//   - For multiple jobs: cluster.proc/filename (e.g., "123.0/input.txt")
//
// Files are spooled in the order they appear in the tar archive.
// Only files listed in the job's TransferInput are spooled.
// Files for jobs not in jobAds are ignored.
//
// jobAds: Array of job ClassAds containing ClusterId, ProcId, and file transfer attributes
// r: Reader providing the tar archive
// Returns: error if the upload fails
func (s *Schedd) SpoolJobFilesFromTar(ctx context.Context, jobAds []*classad.ClassAd, r io.Reader) error {
	if len(jobAds) == 0 {
		return fmt.Errorf("no job ads provided")
	}

	// Extract job IDs and create job info map
	jobIDs, jobInfoMap, err := parseJobAdsForSpooling(jobAds)
	if err != nil {
		return err
	}

	// Prepare security config from context (see SpoolJobFilesFromFS for
	// the same rationale).
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.SPOOL_JOB_FILES_WITH_PERMS, "CLIENT", s.address)
	if err != nil {
		return fmt.Errorf("failed to build security config: %w", err)
	}

	// Connect to schedd and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 3. Send version string
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutString(ctx, "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $"); err != nil {
		return fmt.Errorf("failed to send version string: %w", err)
	}

	// 4. Send number of jobs
	//nolint:gosec // len is bounded by memory, safe to convert to int32
	if err := msg.PutInt32(ctx, int32(len(jobAds))); err != nil {
		return fmt.Errorf("failed to send job count: %w", err)
	}

	// 5. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish initial message: %w", err)
	}

	// 6. Send PROC_ID structures for each job
	msg = message.NewMessageForStream(cedarStream)
	for i, id := range jobIDs {
		if err := msg.PutInt32(ctx, id.cluster); err != nil {
			return fmt.Errorf("failed to send cluster ID for job %d: %w", i, err)
		}
		if err := msg.PutInt32(ctx, id.proc); err != nil {
			return fmt.Errorf("failed to send proc ID for job %d: %w", i, err)
		}
	}

	// 7. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish job IDs message: %w", err)
	}

	// 8. Process tar archive and send files for each job
	singleJobMode := len(jobAds) == 1
	if err := s.sendJobFilesFromTar(ctx, cedarStream, r, jobInfoMap, jobIDs, singleJobMode); err != nil {
		return fmt.Errorf("failed to send files from tar: %w", err)
	}

	return nil
}

// jobInfo holds information about a job for tar processing
type jobInfo struct {
	ad         *classad.ClassAd
	inputFiles map[string]bool // Set of files that should be transferred
	index      int             // Index in the original jobAds array
	jobID      procID
}

// parseJobAdsForSpooling extracts job IDs and builds a map of job info from job ads.
// This includes determining which files need to be transferred for each job.
func parseJobAdsForSpooling(jobAds []*classad.ClassAd) ([]procID, map[procID]*jobInfo, error) {
	jobIDs := make([]procID, len(jobAds))
	jobInfoMap := make(map[procID]*jobInfo)

	for i, ad := range jobAds {
		// Get ClusterId
		clusterExpr, ok := ad.Lookup("ClusterId")
		if !ok {
			return nil, nil, fmt.Errorf("job ad %d missing ClusterId attribute", i)
		}
		clusterVal := clusterExpr.Eval(nil)
		clusterInt, err := clusterVal.IntValue()
		if err != nil {
			return nil, nil, fmt.Errorf("job ad %d: ClusterId is not an integer: %w", i, err)
		}

		// Get ProcId
		procExpr, ok := ad.Lookup("ProcId")
		if !ok {
			return nil, nil, fmt.Errorf("job ad %d missing ProcId attribute", i)
		}
		procVal := procExpr.Eval(nil)
		procInt, err := procVal.IntValue()
		if err != nil {
			return nil, nil, fmt.Errorf("job ad %d: ProcId is not an integer: %w", i, err)
		}

		//nolint:gosec // ClusterId and ProcId are bounded by HTCondor to int32 range
		id := procID{cluster: int32(clusterInt), proc: int32(procInt)}
		jobIDs[i] = id

		// Get list of input files for this job
		inputFileSet := getInputFilesFromJobAd(ad)

		jobInfoMap[id] = &jobInfo{
			ad:         ad,
			inputFiles: inputFileSet,
			index:      i,
			jobID:      id,
		}
	}

	return jobIDs, jobInfoMap, nil
}

// getInputFilesFromJobAd extracts the set of files that need to be transferred for a job.
// This includes TransferInput and the executable if TransferExecutable is true.
func getInputFilesFromJobAd(ad *classad.ClassAd) map[string]bool {
	var inputFiles []string

	transferInputRaw, _ := ad.EvaluateAttrString("TransferInput")
	if transferInputRaw != "" {
		inputFiles = parseFileList(transferInputRaw)
	}

	// Create set of input files for fast lookup
	inputFileSet := make(map[string]bool)
	for _, f := range inputFiles {
		inputFileSet[f] = true
	}

	// Also include the executable if TransferExecutable is true (the default)
	// AND Cmd is a relative path. Absolute paths refer to the worker's
	// filesystem (e.g. "/bin/echo"), not the caller's input FS, so we'd
	// have nothing meaningful to spool — and the caller's FS lookup of the
	// basename would fail with "file does not exist". This matches
	// condor_submit's actual behavior, which only writes TransferExecutable
	// to the ad when the user explicitly sets transfer_executable.
	transferExe := true // default is true
	transferExePresent := false
	if expr, ok := ad.Lookup("TransferExecutable"); ok {
		transferExePresent = true
		val := expr.Eval(nil)
		if b, err := val.BoolValue(); err == nil {
			transferExe = b
		}
	}
	cmdValue := ""
	cmdPresent := false
	if expr, ok := ad.Lookup("Cmd"); ok {
		cmdPresent = true
		val := expr.Eval(nil)
		if cmd, err := val.StringValue(); err == nil {
			cmdValue = cmd
		}
	}
	if transferExe && cmdValue != "" && !path.IsAbs(cmdValue) {
		inputFileSet[path.Base(cmdValue)] = true
	}

	// Log the inputs that went into building the allow-set. Without
	// this it's nearly impossible to tell from a held-job postmortem
	// whether the proc ad's TransferInput was empty, whether Cmd was
	// missing from the projection, or whether Cmd was absolute and
	// therefore (intentionally) excluded. The cluster.proc isn't on
	// the ad at this point, but the caller's logging usually carries
	// it via the surrounding context.
	log.Printf("spool allow-set source: TransferInput=%q Cmd=%q (present=%v) TransferExecutable=%v (present=%v) → set=%v",
		transferInputRaw, cmdValue, cmdPresent, transferExe, transferExePresent, inputFileSet)

	return inputFileSet
}

// sendJobFilesFromTar processes the tar archive and sends files to schedd
//
//nolint:gocyclo // Complex function handling tar streaming, job switching, and file transfer protocol
func (s *Schedd) sendJobFilesFromTar(ctx context.Context, cedarStream *stream.Stream, r io.Reader, jobInfoMap map[procID]*jobInfo, jobIDs []procID, singleJobMode bool) error {
	tarReader := tar.NewReader(r)

	var currentJobID *procID
	var currentJobInfo *jobInfo
	processedJobs := make(map[procID]bool) // Track which jobs have been processed
	peerGoesAheadAlways := false           // Track GoAhead state
	fileIndex := 0                         // Track file index for GoAhead handshake

	// In single job mode, set the current job immediately
	if singleJobMode {
		currentJobID = &jobIDs[0]
		currentJobInfo = jobInfoMap[*currentJobID]

		// Send protocol headers for the single job
		if err := s.sendTransferProtocolHeaders(ctx, cedarStream, 1*1024*1024); err != nil {
			return fmt.Errorf("failed to send protocol headers for job %d.%d: %w", currentJobID.cluster, currentJobID.proc, err)
		}
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar: %w", err)
		}

		// Handle directories - send mkdir command
		if header.Typeflag == tar.TypeDir {
			var dirName string

			if singleJobMode {
				// In single job mode, directories are at root level
				dirName = strings.TrimSuffix(header.Name, "/")
			} else {
				// In multi-job mode, parse cluster.proc/dirname
				parts := strings.SplitN(header.Name, "/", 2)
				if len(parts) != 2 {
					// Directory not in cluster.proc/dirname format, skip
					continue
				}

				// Parse cluster.proc
				procParts := strings.SplitN(parts[0], ".", 2)
				if len(procParts) != 2 {
					// Not in cluster.proc format, skip
					continue
				}

				cluster, err := strconv.ParseInt(procParts[0], 10, 32)
				if err != nil {
					// Invalid cluster ID, skip
					continue
				}

				proc, err := strconv.ParseInt(procParts[1], 10, 32)
				if err != nil {
					// Invalid proc ID, skip
					continue
				}

				parsedJobID := procID{cluster: int32(cluster), proc: int32(proc)}
				dirName = strings.TrimSuffix(parts[1], "/")

				// Check if this job is in our list
				if _, ok := jobInfoMap[parsedJobID]; !ok {
					// Job not in our list, skip
					continue
				}

				// Check if we're switching to a new job
				if currentJobID == nil || *currentJobID != parsedJobID {
					// Send CommandFinished for the previous job if there was one
					if currentJobID != nil && currentJobInfo != nil {
						if err := s.sendCommandFinished(ctx, cedarStream); err != nil {
							return fmt.Errorf("failed to send CommandFinished for job %d.%d: %w", currentJobID.cluster, currentJobID.proc, err)
						}
						processedJobs[*currentJobID] = true
					}

					// Switch to new job
					currentJobID = &parsedJobID
					currentJobInfo = jobInfoMap[parsedJobID]

					// Reset file index and GoAhead state for new job
					fileIndex = 0
					peerGoesAheadAlways = false

					// Send protocol headers for this job
					if err := s.sendTransferProtocolHeaders(ctx, cedarStream, 1*1024*1024); err != nil {
						return fmt.Errorf("failed to send protocol headers for job %d.%d: %w", parsedJobID.cluster, parsedJobID.proc, err)
					}
				}
			}

			// Send CommandMkdir
			if dirName != "" && dirName != "." {
				log.Printf("Sending mkdir command for: %s", dirName)
				msg := message.NewMessageForStream(cedarStream)
				if err := msg.PutInt32(ctx, int32(CommandMkdir)); err != nil {
					return fmt.Errorf("failed to send CommandMkdir: %w", err)
				}
				if err := msg.FinishMessage(ctx); err != nil {
					return fmt.Errorf("failed to finish CommandMkdir message: %w", err)
				}

				// Send directory name
				msg = message.NewMessageForStream(cedarStream)
				if err := msg.PutString(ctx, dirName); err != nil {
					return fmt.Errorf("failed to send directory name: %w", err)
				}
				if err := msg.FinishMessage(ctx); err != nil {
					return fmt.Errorf("failed to finish directory name message: %w", err)
				}
			}

			continue
		}

		// Only process regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		var fileName string

		if singleJobMode {
			// In single job mode, files are at root level
			fileName = header.Name
		} else {
			// In multi-job mode, parse cluster.proc/filename
			parts := strings.SplitN(header.Name, "/", 2)
			if len(parts) != 2 {
				// File not in cluster.proc/filename format, skip
				continue
			}

			// Parse cluster.proc
			procParts := strings.SplitN(parts[0], ".", 2)
			if len(procParts) != 2 {
				// Not in cluster.proc format, skip
				continue
			}

			cluster, err := strconv.ParseInt(procParts[0], 10, 32)
			if err != nil {
				// Invalid cluster ID, skip
				continue
			}

			proc, err := strconv.ParseInt(procParts[1], 10, 32)
			if err != nil {
				// Invalid proc ID, skip
				continue
			}

			parsedJobID := procID{cluster: int32(cluster), proc: int32(proc)}
			fileName = parts[1]

			// Check if this job is in our list
			if _, ok := jobInfoMap[parsedJobID]; !ok {
				// Job not in our list, skip all its files
				continue
			}

			// Check if we're switching to a new job
			if currentJobID == nil || *currentJobID != parsedJobID {
				// Send CommandFinished for the previous job if there was one
				if currentJobID != nil && currentJobInfo != nil {
					if err := s.sendCommandFinished(ctx, cedarStream); err != nil {
						return fmt.Errorf("failed to send CommandFinished for job %d.%d: %w", currentJobID.cluster, currentJobID.proc, err)
					}
					processedJobs[*currentJobID] = true
				}

				// Switch to new job
				currentJobID = &parsedJobID
				currentJobInfo = jobInfoMap[parsedJobID]

				// Reset file index and GoAhead state for new job
				fileIndex = 0
				peerGoesAheadAlways = false

				// Send protocol headers for this job (final_transfer flag, xfer_info ClassAd)
				if err := s.sendTransferProtocolHeaders(ctx, cedarStream, 1*1024*1024); err != nil {
					return fmt.Errorf("failed to send protocol headers for job %d.%d: %w", parsedJobID.cluster, parsedJobID.proc, err)
				}
			}
		}

		// Check if this file should be transferred
		if currentJobInfo == nil || !currentJobInfo.inputFiles[fileName] {
			// File not in the input files list, skip it. Log a
			// warning so the silent drop is visible when something
			// references a file we never spool — e.g., the SPA
			// uploaded an inline script "run.sh" but the proc ad
			// projection didn't pull Cmd / TransferExecutable, so
			// getInputFilesFromJobAd never folded run.sh into the
			// allow-set. Without this log line the symptom is the
			// schedd holding the job at execute-time with ENOENT
			// and no clue why.
			if currentJobInfo == nil {
				log.Printf("spool: skipping %s: no current job in stream", fileName)
			} else {
				allowed := make([]string, 0, len(currentJobInfo.inputFiles))
				for k := range currentJobInfo.inputFiles {
					allowed = append(allowed, k)
				}
				log.Printf("spool: skipping %s for job %d.%d (not in allow-set %v) — check that the proc ad's TransferInput/Cmd/TransferExecutable cover this file",
					fileName, currentJobInfo.jobID.cluster, currentJobInfo.jobID.proc, allowed)
			}
			continue
		}

		// Stream this file to schedd using the common protocol
		fileSize := header.Size
		fileMode := header.FileInfo().Mode().Perm()

		// Use the shared sendSingleFile function with tarReader as the file reader
		if err := s.sendSingleFile(ctx, cedarStream, fileName, fileSize, int64(fileMode), tarReader, &peerGoesAheadAlways, fileIndex); err != nil {
			return err
		}

		fileIndex++
	}

	// Send CommandFinished for the last job
	if currentJobID != nil {
		if err := s.sendCommandFinished(ctx, cedarStream); err != nil {
			return fmt.Errorf("failed to send final CommandFinished: %w", err)
		}
		processedJobs[*currentJobID] = true
	}

	// Send CommandFinished for any jobs that had no files (must send for each job in order)
	for _, jobID := range jobIDs {
		if !processedJobs[jobID] {
			// This job had no files, send protocol headers and CommandFinished
			if err := s.sendTransferProtocolHeaders(ctx, cedarStream, 0); err != nil {
				return fmt.Errorf("failed to send protocol headers for job %d.%d: %w", jobID.cluster, jobID.proc, err)
			}
			if err := s.sendCommandFinished(ctx, cedarStream); err != nil {
				return fmt.Errorf("failed to send CommandFinished for job %d.%d: %w", jobID.cluster, jobID.proc, err)
			}
		}
	}

	return nil
}

// sendCommandFinished sends a CommandFinished message and receives the transfer acknowledgment
// This follows the same protocol as the end of sendJobFiles (ExitDoUpload)
func (s *Schedd) sendCommandFinished(ctx context.Context, cedarStream *stream.Stream) error {
	return filetransfer.SendFinished(ctx, cedarStream, ftOpts)
}

// sendTransferProtocolHeaders sends the file transfer protocol headers required before sending files
// This includes the final_transfer flag and xfer_info ClassAd with SandboxSize
func (s *Schedd) sendTransferProtocolHeaders(ctx context.Context, cedarStream *stream.Stream, sandboxSize int64) error {
	return filetransfer.SendPreamble(ctx, cedarStream, sandboxSize, false, ftOpts)
}

// releaseJobsWithEmptySpool performs an empty spool for jobs that don't need input files.
// This triggers the schedd to release the job from the hold state and set the Iwd.
func (s *Schedd) releaseJobsWithEmptySpool(ctx context.Context, jobAds []*classad.ClassAd) error {
	// Create an empty tarball
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		_ = tw.Close()
		_ = pw.Close()
	}()

	return s.SpoolJobFilesFromTar(ctx, jobAds, pr)
}

// OutputRemap represents a single output file remap entry
type OutputRemap struct {
	Source      string // Original filename from the job sandbox
	Destination string // Remapped destination path or URL
	IsURL       bool   // True if destination is a URL (should be skipped in tarball)
}

// parseOutputRemaps parses the TransferOutputRemaps format: "name1=path1;name2=path2"
// Supports escaped characters: \= for literal = and \; for literal ;
// If the destination is a URL (s3://, http://, https://, etc.), IsURL is set to true.
// Returns a slice of OutputRemap structs preserving order.
func parseOutputRemaps(remaps string) []OutputRemap {
	if remaps == "" {
		return nil
	}

	var result []OutputRemap

	// Parse with escape handling
	// Split by semicolons, respecting escaped semicolons (\;)
	pairs := splitWithEscape(remaps, ';')

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split by first =, respecting escaped equals (\=)
		src, dst, found := splitFirstWithEscape(pair, '=')
		if !found {
			continue
		}

		src = strings.TrimSpace(src)
		dst = strings.TrimSpace(dst)

		if src == "" || dst == "" {
			continue
		}

		// Unescape the strings
		src = unescapeRemapString(src)
		dst = unescapeRemapString(dst)

		result = append(result, OutputRemap{
			Source:      src,
			Destination: dst,
			IsURL:       isURL(dst),
		})
	}

	return result
}

// splitWithEscape splits a string by a delimiter, respecting backslash escapes.
// For example, "a\;b;c" with delimiter ';' returns ["a;b", "c"]
func splitWithEscape(s string, delim byte) []string {
	var result []string
	var current strings.Builder

	i := 0
	for i < len(s) {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			// Escape sequence - include next character literally
			current.WriteByte(s[i])
			current.WriteByte(s[i+1])
			i += 2
		case s[i] == delim:
			result = append(result, current.String())
			current.Reset()
			i++
		default:
			current.WriteByte(s[i])
			i++
		}
	}
	result = append(result, current.String())
	return result
}

// splitFirstWithEscape splits a string at the first unescaped occurrence of the delimiter.
// Returns (before, after, true) if found, or (s, "", false) if not found.
func splitFirstWithEscape(s string, delim byte) (string, string, bool) {
	i := 0
	for i < len(s) {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			// Skip escape sequence
			i += 2
		case s[i] == delim:
			return s[:i], s[i+1:], true
		default:
			i++
		}
	}
	return s, "", false
}

// unescapeRemapString removes backslash escapes from a string.
// Handles \= and \; specifically, and removes any other backslash escapes.
func unescapeRemapString(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			// Unescape: skip the backslash and include the next character
			result.WriteByte(s[i+1])
			i += 2
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}

// isURL checks if a path looks like a URL (has a scheme://)
// Common schemes: s3://, http://, https://, gs://, file://, osdf://, etc.
// Per RFC 3986, schemes must start with a letter.
func isURL(path string) bool {
	// Look for scheme://
	idx := strings.Index(path, "://")
	if idx <= 0 {
		return false
	}
	// Check that scheme starts with a letter (RFC 3986)
	scheme := path[:idx]
	if len(scheme) == 0 {
		return false
	}
	firstChar := scheme[0]
	isLetter := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	if !isLetter(firstChar) {
		return false
	}
	// Rest of scheme can be letters, digits, +, -, .
	isValidSchemeChar := func(c byte) bool {
		return isLetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
	}
	for i := 1; i < len(scheme); i++ {
		if !isValidSchemeChar(scheme[i]) {
			return false
		}
	}
	return true
}

// buildRemapLookup converts a slice of OutputRemaps to a map for fast lookup.
// The map key is the source filename, value is the OutputRemap.
func buildRemapLookup(remaps []OutputRemap) map[string]OutputRemap {
	lookup := make(map[string]OutputRemap)
	for _, r := range remaps {
		lookup[r.Source] = r
	}
	return lookup
}

// applyOutputRemap looks up a filename in the remap table and returns the remapped path.
// It supports both exact matches and prefix-based directory remapping.
// For prefix matching, if a remap source matches the start of the filename followed by a path separator,
// the matching prefix is replaced with the destination.
// For example, remap "result_files=files" will map "result_files/foo.txt" to "files/foo.txt".
// Returns (remappedPath, remap, found). If found is false, the file has no remap.
// If the remap destination is a URL, the caller should skip the file.
func applyOutputRemap(fileName string, remaps map[string]OutputRemap) (string, OutputRemap, bool) {
	// First, try exact match
	if remap, found := remaps[fileName]; found {
		return remap.Destination, remap, true
	}

	// Try prefix-based directory remapping
	// Look for remaps where the source matches the beginning of fileName followed by "/"
	for source, remap := range remaps {
		// Check if fileName starts with "source/"
		prefix := source + "/"
		if strings.HasPrefix(fileName, prefix) {
			// Replace the prefix with the destination
			suffix := fileName[len(prefix):]
			remappedPath := remap.Destination + "/" + suffix
			return remappedPath, remap, true
		}
	}

	return fileName, OutputRemap{}, false
}
