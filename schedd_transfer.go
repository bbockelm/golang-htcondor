package htcondor

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

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
	// 1. Connect to schedd using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, s.address)
	if err != nil {
		return fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.TRANSFER_DATA_WITH_PERMS, "CLIENT", s.address)
	if err != nil {
		return fmt.Errorf("failed to create security config: %w", err)
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	_, err = auth.ClientHandshake(ctx)
	if err != nil {
		return fmt.Errorf("security handshake failed: %w", err)
	}

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
		// a. Receive job ClassAd
		responseMsg = message.NewMessageFromStream(cedarStream)
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

		// Get list of transfer output files (if specified)
		var transferOutputFiles map[string]bool
		if expr, ok := jobAd.Lookup("TransferOutputFiles"); ok {
			val := expr.Eval(nil)
			if str, err := val.StringValue(); err == nil && str != "" {
				fileList := parseFileList(str)
				transferOutputFiles = make(map[string]bool)
				for _, f := range fileList {
					transferOutputFiles[f] = true
				}
			}
		}

		// c-e. Receive files using FileTransfer protocol
		// First receive the transfer protocol headers (final_transfer flag and xfer_info)
		headerMsg := message.NewMessageFromStream(cedarStream)

		// Read final_transfer flag
		finalTransfer, err := headerMsg.GetInt32(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive final_transfer flag: %w", err)
		}
		_ = finalTransfer // 0 = intermediate, 1 = final

		// Read xfer_info ClassAd
		xferInfo, err := headerMsg.GetClassAd(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive xfer_info ClassAd: %w", err)
		}
		_ = xferInfo // Contains SandboxSize
		// EOM after xfer_info (implicit)

		// Now receive the files
		if err := s.receiveJobFiles(ctx, cedarStream, tarWriter, dirPrefix, transferOutputFiles); err != nil {
			return fmt.Errorf("failed to receive files for job %d.%d: %w", clusterID, procID, err)
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

// receiveJobFiles receives files for a single job and writes them to the tar archive
//
//nolint:gocyclo // Complex function required for HTCondor file transfer protocol
func (s *Schedd) receiveJobFiles(ctx context.Context, cedarStream *stream.Stream, tarWriter *tar.Writer, dirPrefix string, transferOutputFiles map[string]bool) error {
	// Track whether we've received GO_AHEAD_ALWAYS from the peer
	goAheadAlways := false

	for {
		// Read transfer command
		msg := message.NewMessageFromStream(cedarStream)
		cmd, err := msg.GetInt32(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive transfer command: %w", err)
		}

		transferCmd := TransferCommand(cmd)

		// EOM after command (implicit)

		switch transferCmd {
		case CommandFinished:
			// End of files for this job
			return nil

		case CommandXferFile:
			// Protocol for receiving a file:
			// 1. Read filename (string) - no EOM yet
			// 2. If PeerDoesGoAhead: EOM, then GoAhead exchange
			// 3. Read file_mode (int32/int64) + EOM (from get_file_with_permissions)
			// 4. Read file_size (int64) + buffer_size (int32) + file data

			msg = message.NewMessageFromStream(cedarStream)
			fileName, err := msg.GetString(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive filename: %w", err)
			}

			// Modern HTCondor uses GoAhead protocol
			// Perform bidirectional GoAhead handshake (only on first file if GO_AHEAD_ALWAYS is set)
			if !goAheadAlways {
				// Constants from file_transfer.cpp
				const (
					goAheadAlwaysValue = 2 // Peer will send all files without asking again
				)

				// 1. Receive server's alive_interval request
				serverAliveMsg := message.NewMessageFromStream(cedarStream)
				serverAliveInterval, err := serverAliveMsg.GetInt32(ctx)
				if err != nil {
					return fmt.Errorf("failed to receive server alive_interval: %w", err)
				}
				_ = serverAliveInterval // Acknowledge it
				// EOM after alive_interval (implicit)

				// 2. Send GoAhead response to server
				clientGoAhead := classad.New()
				_ = clientGoAhead.Set("Result", int64(goAheadAlwaysValue)) // We always go ahead
				_ = clientGoAhead.Set("Timeout", int64(300))

				goAheadMsg := message.NewMessageForStream(cedarStream)
				if err := goAheadMsg.PutClassAd(ctx, clientGoAhead); err != nil {
					return fmt.Errorf("failed to send client GoAhead: %w", err)
				}
				if err := goAheadMsg.FinishMessage(ctx); err != nil {
					return fmt.Errorf("failed to finish client GoAhead message: %w", err)
				}

				// 3. Send our alive_interval request
				aliveMsg := message.NewMessageForStream(cedarStream)
				aliveInterval := int32(300) // 5 minutes
				if err := aliveMsg.PutInt32(ctx, aliveInterval); err != nil {
					return fmt.Errorf("failed to send alive_interval: %w", err)
				}
				if err := aliveMsg.FinishMessage(ctx); err != nil {
					return fmt.Errorf("failed to finish alive_interval message: %w", err)
				}

				// 4. Receive server's GoAhead ClassAd
				serverGoAheadMsg := message.NewMessageFromStream(cedarStream)
				serverGoAheadAd, err := serverGoAheadMsg.GetClassAd(ctx)
				if err != nil {
					return fmt.Errorf("failed to receive GoAhead from server: %w", err)
				}

				// Check Result in GoAhead
				resultExpr, ok := serverGoAheadAd.Lookup("Result")
				if !ok {
					return fmt.Errorf("GoAhead missing Result attribute")
				}
				resultVal := resultExpr.Eval(nil)
				result, err := resultVal.IntValue()
				if err != nil || result <= 0 {
					return fmt.Errorf("GoAhead failed: Result=%v", result)
				}

				// Check if we got GO_AHEAD_ALWAYS - if so, no more handshakes needed
				if result == goAheadAlwaysValue {
					goAheadAlways = true
					log.Printf("Received GO_AHEAD_ALWAYS - no more handshakes needed")
				}
				// EOM after GoAhead (implicit)

				log.Printf("Completed GoAhead handshake for %s", fileName)
			} else {
				log.Printf("Skipping GoAhead handshake for %s (GO_AHEAD_ALWAYS set)", fileName)
			}

			// Read file permissions (from get_file_with_permissions)
			msg = message.NewMessageFromStream(cedarStream)
			fileMode, err := msg.GetInt64(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive file permissions: %w", err)
			}
			// EOM after permissions (implicit)

			// Read file size and buffer size (from get_file/put_file protocol)
			msg = message.NewMessageFromStream(cedarStream)
			fileSize, err := msg.GetInt64(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive file size: %w", err)
			}

			// Read buffer size (for AES encrypted transfers)
			bufferSize, err := msg.GetInt32(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive buffer size: %w", err)
			}
			_ = bufferSize // We know the buffer size but will read in chunks
			// EOM after size/buffer (implicit)

			// Check if this file should be transferred (if filter is set)
			if transferOutputFiles != nil && !transferOutputFiles[fileName] {
				// File not in the output files list, skip it by reading and discarding
				discarded := int64(0)
				const maxChunkSize = 256 * 1024
				for discarded < fileSize {
					remaining := fileSize - discarded
					chunkSize := remaining
					if chunkSize > maxChunkSize {
						chunkSize = maxChunkSize
					}

					chunkMsg := message.NewMessageFromStream(cedarStream)
					_, err := chunkMsg.GetBytes(ctx, int(chunkSize))
					if err != nil {
						return fmt.Errorf("failed to discard file data: %w", err)
					}
					discarded += chunkSize
				}
				log.Printf("Skipped file %s (not in TransferOutputFiles)", fileName)
				continue
			}

			// Resolve relative path and ensure it stays within dirPrefix
			cleanPath := path.Clean(fileName)
			if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/../") {
				// Path tries to escape, log and skip
				log.Printf("Ignoring file with path traversal: %s", fileName)
				// Read and discard the file data
				discarded := int64(0)
				const maxChunkSize = 256 * 1024
				for discarded < fileSize {
					remaining := fileSize - discarded
					chunkSize := remaining
					if chunkSize > maxChunkSize {
						chunkSize = maxChunkSize
					}

					chunkMsg := message.NewMessageFromStream(cedarStream)
					_, err := chunkMsg.GetBytes(ctx, int(chunkSize))
					if err != nil {
						return fmt.Errorf("failed to discard file data: %w", err)
					}
					discarded += chunkSize
				}
				continue
			}

			// Build full path in tar: dirPrefix/fileName
			tarPath := path.Join(dirPrefix, cleanPath)

			// Write tar header
			header := &tar.Header{
				Name:    tarPath,
				Size:    fileSize,
				Mode:    fileMode,
				ModTime: time.Now(),
			}

			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("failed to write tar header for %s: %w", tarPath, err)
			}

			// Stream file data directly to tar
			// File data comes in chunks, each chunk is a separate CEDAR message
			totalRead := int64(0)
			const maxChunkSize = 256 * 1024 // Match AES buffer size from sender
			for totalRead < fileSize {
				// Calculate chunk size for this read
				remaining := fileSize - totalRead
				chunkSize := remaining
				if chunkSize > maxChunkSize {
					chunkSize = maxChunkSize
				}

				// Each chunk is a separate message
				chunkMsg := message.NewMessageFromStream(cedarStream)
				chunkData, err := chunkMsg.GetBytes(ctx, int(chunkSize))
				if err != nil {
					return fmt.Errorf("failed to read file data chunk for %s: %w", fileName, err)
				}
				// EOM after chunk (implicit)

				if _, err := tarWriter.Write(chunkData); err != nil {
					return fmt.Errorf("failed to write to tar for %s: %w", fileName, err)
				}

				totalRead += int64(len(chunkData))
			}

			if totalRead != fileSize {
				return fmt.Errorf("file size mismatch for %s: expected %d, got %d", fileName, fileSize, totalRead)
			}

		case CommandMkdir:
			// Read directory name
			msg = message.NewMessageFromStream(cedarStream)
			dirName, err := msg.GetString(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive directory name: %w", err)
			}
			// EOM (implicit)

			// Resolve path
			cleanPath := path.Clean(dirName)
			if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/../") {
				log.Printf("Ignoring directory with path traversal: %s", dirName)
				continue
			}

			// Build full path in tar: dirPrefix/dirName
			tarPath := path.Join(dirPrefix, cleanPath)

			// Write directory entry to tar
			header := &tar.Header{
				Name:     tarPath + "/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
			}

			if err := tarWriter.WriteHeader(header); err != nil {
				return fmt.Errorf("failed to write tar header for directory %s: %w", tarPath, err)
			}

		default:
			// Unknown command, skip it
			log.Printf("Unknown transfer command: %d", cmd)
		}
	}
}

// SpoolJobFilesFromFS uploads input files to the schedd for the specified jobs.
// Files are read from the provided filesystem.
//
// The input files to transfer are determined from each job ad's TransferInputFiles attribute.
// If TransferInputFiles is not present, an error is returned.
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
// jobAds: Array of job ClassAds containing ClusterId, ProcId, and TransferInputFiles
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

		// Get TransferInputFiles - this contains the comma-separated list of input files
		transferInputFilesExpr, ok := ad.Lookup("TransferInputFiles")
		if !ok {
			return fmt.Errorf("job ad %d (job %d.%d) missing TransferInputFiles attribute", i, clusterInt, procInt)
		}

		// Get the string representation
		transferInputStr := transferInputFilesExpr.String()
		transferInputStr = strings.Trim(transferInputStr, "\"") // Remove quotes if present

		if transferInputStr == "" || transferInputStr == "UNDEFINED" {
			return fmt.Errorf("job ad %d (job %d.%d): TransferInputFiles is empty or undefined", i, clusterInt, procInt)
		}

		// Parse the file list
		fileLists[i] = parseFileList(transferInputStr)
		if len(fileLists[i]) == 0 {
			return fmt.Errorf("job ad %d (job %d.%d): parsed file list is empty", i, clusterInt, procInt)
		}
	}

	// 1. Connect to schedd using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, s.address)
	if err != nil {
		return fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 2. Perform DC_AUTHENTICATE handshake with SPOOL_JOB_FILES_WITH_PERMS
	secConfig := &security.SecurityConfig{
		Command:        commands.SPOOL_JOB_FILES_WITH_PERMS,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	_, err = auth.ClientHandshake(ctx)
	if err != nil {
		return fmt.Errorf("security handshake failed: %w", err)
	}

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

// sendSingleFile sends a single file using the HTCondor file transfer protocol
// This implements the per-file protocol from FileTransfer and ReliSock
func (s *Schedd) sendSingleFile(ctx context.Context, cedarStream *stream.Stream, fileName string, fileSize int64, fileMode int64, fileReader io.Reader, peerGoesAheadAlways *bool, fileIndex int) error {
	log.Printf("Sending file: %s", fileName)

	// Send CommandXferFile
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(CommandXferFile)); err != nil {
		return fmt.Errorf("failed to send CommandXferFile: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish CommandXferFile message: %w", err)
	}

	// Send filename
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutString(ctx, fileName); err != nil {
		return fmt.Errorf("failed to send filename: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish filename message: %w", err)
	}

	// GoAhead protocol constants from file_transfer.cpp
	const (
		goAheadAlways = 2 // send all files without asking again
	)

	// Perform bidirectional GoAhead handshake (only for first file, or if not GO_AHEAD_ALWAYS)
	if fileIndex == 0 || !*peerGoesAheadAlways {
		// 1. Client sends alive_interval
		msg = message.NewMessageForStream(cedarStream)
		aliveInterval := int32(300) // 5 minutes
		if err := msg.PutInt32(ctx, aliveInterval); err != nil {
			return fmt.Errorf("failed to send alive_interval: %w", err)
		}
		if err := msg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to finish alive_interval message: %w", err)
		}

		// 2. Client receives GoAhead ClassAd from server
		goAheadMsg := message.NewMessageFromStream(cedarStream)
		goAheadAd, err := goAheadMsg.GetClassAd(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive GoAhead from server: %w", err)
		}

		// Check Result in GoAhead
		resultExpr, ok := goAheadAd.Lookup("Result")
		if !ok {
			return fmt.Errorf("GoAhead missing Result attribute")
		}
		resultVal := resultExpr.Eval(nil)
		result, err := resultVal.IntValue()
		if err != nil || result <= 0 {
			return fmt.Errorf("GoAhead failed: Result=%v", result)
		}

		// Check if we got goAheadAlways
		if result == goAheadAlways {
			*peerGoesAheadAlways = true
			log.Printf("  Received GO_AHEAD_ALWAYS - no more handshakes needed")
		}

		// 3. Server sends alive_interval request - receive it
		serverAliveMsg := message.NewMessageFromStream(cedarStream)
		serverAliveInterval, err := serverAliveMsg.GetInt32(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive server alive_interval: %w", err)
		}
		_ = serverAliveInterval // Just acknowledge it

		// 4. Client sends GoAhead response back to server
		clientGoAhead := classad.New()
		_ = clientGoAhead.Set("Result", int64(goAheadAlways)) // We always go ahead
		_ = clientGoAhead.Set("Timeout", int64(300))

		msg = message.NewMessageForStream(cedarStream)
		if err := msg.PutClassAd(ctx, clientGoAhead); err != nil {
			return fmt.Errorf("failed to send client GoAhead: %w", err)
		}
		if err := msg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to finish client GoAhead message: %w", err)
		}

		log.Printf("  Completed GoAhead handshake for %s", fileName)
	} else {
		log.Printf("  Skipping GoAhead handshake (GO_AHEAD_ALWAYS already set)")
	}

	// Step 1: Send file permissions as SEPARATE message
	msg = message.NewMessageForStream(cedarStream)
	//nolint:gosec // File mode is limited to 12 bits (0777), safe to convert to int32
	if err := msg.PutInt32(ctx, int32(fileMode)); err != nil {
		return fmt.Errorf("failed to send file permissions: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish permissions message: %w", err)
	}

	// Step 2: Send file size + buffer size as SEPARATE message
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt64(ctx, fileSize); err != nil {
		return fmt.Errorf("failed to send file size: %w", err)
	}

	// Send buffer size for AESGCM encrypted transfers (256KB)
	const aesBufferSize = int32(256 * 1024) // AES_FILE_BUF_SZ from C++
	if err := msg.PutInt32(ctx, aesBufferSize); err != nil {
		return fmt.Errorf("failed to send buffer size: %w", err)
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish file size message: %w", err)
	}

	// Stream file data in chunks matching the buffer size we advertised (256KB for AES)
	const aesChunkSize = 256 * 1024
	buffer := make([]byte, aesChunkSize)
	var totalRead int64

	for {
		n, err := fileReader.Read(buffer)
		if n > 0 {
			// In buffered mode, each chunk is a separate CEDAR message
			chunkMsg := message.NewMessageForStream(cedarStream)
			if err := chunkMsg.PutBytes(ctx, buffer[:n]); err != nil {
				return fmt.Errorf("failed to send file data chunk for %s: %w", fileName, err)
			}
			if err := chunkMsg.FinishMessage(ctx); err != nil {
				return fmt.Errorf("failed to finish file data chunk message for %s: %w", fileName, err)
			}
			totalRead += int64(n)
		}

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read file data for %s: %w", fileName, err)
		}
	}

	if totalRead != fileSize {
		return fmt.Errorf("file size mismatch for %s: expected %d, read %d", fileName, fileSize, totalRead)
	}

	log.Printf("  Successfully sent %d bytes for %s", totalRead, fileName)
	return nil
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

	// Calculate total sandbox size for all files
	var sandboxSize int64
	for _, filePath := range inputFiles {
		fileInfo, err := fs.Stat(fsys, filePath)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", filePath, err)
		}
		sandboxSize += fileInfo.Size()
	}

	// 1. Send final_transfer flag (0 = intermediate transfer, files go to spool)
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(0)); err != nil {
		return fmt.Errorf("failed to send final_transfer flag: %w", err)
	}

	// 2. Send xfer_info ClassAd (protocol version >= 8.1.0)
	// This contains ATTR_SANDBOX_SIZE to tell the schedd how much data to expect
	xferInfo := classad.New()
	_ = xferInfo.Set("SandboxSize", sandboxSize)
	if err := msg.PutClassAd(ctx, xferInfo); err != nil {
		return fmt.Errorf("failed to send xfer_info ClassAd: %w", err)
	}

	// 3. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish xfer_info message: %w", err)
	}

	// Track whether we have GO_AHEAD_ALWAYS from the schedd
	peerGoesAheadAlways := false

	// Send each file (or just CommandFinished if no files)
	if len(inputFiles) > 0 {
		for i, filePath := range inputFiles {
			// Open and read file
			file, err := fsys.Open(filePath)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", filePath, err)
			}

			// Get file info for size and permissions
			stat, err := file.Stat()
			if err != nil {
				_ = file.Close()
				return fmt.Errorf("failed to stat file %s: %w", filePath, err)
			}
			fileSize := stat.Size()
			fileMode := stat.Mode().Perm()

			log.Printf("  File size: %d bytes, mode: %o", fileSize, fileMode)

			// Send the file using the common protocol
			if err := s.sendSingleFile(ctx, cedarStream, filePath, fileSize, int64(fileMode), file, &peerGoesAheadAlways, i); err != nil {
				_ = file.Close()
				return err
			}

			_ = file.Close()
		}
	}

	log.Printf("Sending CommandFinished")

	// Send CommandFinished
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(CommandFinished)); err != nil {
		return fmt.Errorf("failed to send CommandFinished: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish CommandFinished message: %w", err)
	}

	// Per ExitDoUpload (file_transfer.cpp:6101), after CommandFinished, the client must
	// send a TransferAck to the schedd before receiving the schedd's TransferAck
	log.Printf("Sending upload TransferAck")
	uploadAck := classad.New()
	_ = uploadAck.Set("Result", int64(0)) // 0 = success

	// Add TransferStats (empty for now, but required)
	transferStats := classad.New()
	_ = uploadAck.Set("TransferStats", transferStats)

	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, uploadAck); err != nil {
		return fmt.Errorf("failed to send upload TransferAck: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish upload TransferAck: %w", err)
	}

	// Now receive download TransferAck from schedd
	log.Printf("Waiting for download TransferAck from schedd")
	ackMsg := message.NewMessageFromStream(cedarStream)
	ackAd, err := ackMsg.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive download TransferAck: %w", err)
	}

	log.Printf("Received transfer acknowledgment: %s", ackAd.String())

	// Check result in ack
	resultExpr, ok := ackAd.Lookup("Result")
	if !ok {
		return fmt.Errorf("transfer ack missing Result attribute")
	}
	resultVal := resultExpr.Eval(nil)
	result, err := resultVal.IntValue()
	if err != nil {
		return fmt.Errorf("transfer ack Result is not an integer: %w", err)
	}

	if result != 0 {
		// Transfer failed - extract error details if available
		var holdReason string
		if expr, ok := ackAd.Lookup("HoldReason"); ok {
			val := expr.Eval(nil)
			if str, err := val.StringValue(); err == nil {
				holdReason = str
			}
		}
		if holdReason != "" {
			return fmt.Errorf("transfer failed (result=%d): %s", result, holdReason)
		}
		return fmt.Errorf("transfer failed (result=%d)", result)
	}

	return nil
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
// Only files listed in the job's TransferInputFiles are spooled.
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
	jobIDs := make([]procID, len(jobAds))
	jobInfoMap := make(map[procID]*jobInfo)

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
		id := procID{cluster: int32(clusterInt), proc: int32(procInt)}
		jobIDs[i] = id

		// Get list of input files for this job
		var inputFiles []string
		if expr, ok := ad.Lookup("TransferInputFiles"); ok {
			val := expr.Eval(nil)
			if str, err := val.StringValue(); err == nil && str != "" {
				inputFiles = parseFileList(str)
			}
		}
		if len(inputFiles) == 0 {
			if expr, ok := ad.Lookup("TransferInput"); ok {
				val := expr.Eval(nil)
				if str, err := val.StringValue(); err == nil && str != "" {
					inputFiles = parseFileList(str)
				}
			}
		}

		// Create set of input files for fast lookup
		inputFileSet := make(map[string]bool)
		for _, f := range inputFiles {
			inputFileSet[f] = true
		}

		jobInfoMap[id] = &jobInfo{
			ad:         ad,
			inputFiles: inputFileSet,
			index:      i,
			jobID:      id,
		}
	}

	// 1. Connect to schedd using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, s.address)
	if err != nil {
		return fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 2. Perform DC_AUTHENTICATE handshake with SPOOL_JOB_FILES_WITH_PERMS
	secConfig := &security.SecurityConfig{
		Command:        commands.SPOOL_JOB_FILES_WITH_PERMS,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	_, err = auth.ClientHandshake(ctx)
	if err != nil {
		return fmt.Errorf("security handshake failed: %w", err)
	}

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
			// File not in the input files list, skip it
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
	log.Printf("Sending CommandFinished")

	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(CommandFinished)); err != nil {
		return fmt.Errorf("failed to send CommandFinished: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish CommandFinished message: %w", err)
	}

	// Per ExitDoUpload (file_transfer.cpp:6101), after CommandFinished, the client must
	// send a TransferAck to the schedd before receiving the schedd's TransferAck
	log.Printf("Sending upload TransferAck")
	uploadAck := classad.New()
	_ = uploadAck.Set("Result", int64(0)) // 0 = success

	// Add TransferStats (empty for now, but required)
	transferStats := classad.New()
	_ = uploadAck.Set("TransferStats", transferStats)

	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, uploadAck); err != nil {
		return fmt.Errorf("failed to send upload TransferAck: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish upload TransferAck: %w", err)
	}

	// Now receive download TransferAck from schedd
	log.Printf("Waiting for download TransferAck from schedd")
	ackMsg := message.NewMessageFromStream(cedarStream)
	ackAd, err := ackMsg.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive download TransferAck: %w", err)
	}

	log.Printf("Received transfer acknowledgment: %s", ackAd.String())

	// Check result in ack
	resultExpr, ok := ackAd.Lookup("Result")
	if !ok {
		return fmt.Errorf("transfer ack missing Result attribute")
	}
	resultVal := resultExpr.Eval(nil)
	result, err := resultVal.IntValue()
	if err != nil {
		return fmt.Errorf("transfer ack Result is not an integer: %w", err)
	}

	if result != 0 {
		// Transfer failed - extract error details if available
		var holdReason string
		if expr, ok := ackAd.Lookup("HoldReason"); ok {
			val := expr.Eval(nil)
			if str, err := val.StringValue(); err == nil {
				holdReason = str
			}
		}
		if holdReason != "" {
			return fmt.Errorf("transfer failed (result=%d): %s", result, holdReason)
		}
		return fmt.Errorf("transfer failed (result=%d)", result)
	}

	return nil
}

// sendTransferProtocolHeaders sends the file transfer protocol headers required before sending files
// This includes the final_transfer flag and xfer_info ClassAd with SandboxSize
func (s *Schedd) sendTransferProtocolHeaders(ctx context.Context, cedarStream *stream.Stream, sandboxSize int64) error {
	// 1. Send final_transfer flag (0 = intermediate transfer, files go to spool)
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(0)); err != nil {
		return fmt.Errorf("failed to send final_transfer flag: %w", err)
	}

	// 2. Send xfer_info ClassAd (protocol version >= 8.1.0)
	xferInfo := classad.New()
	_ = xferInfo.Set("SandboxSize", sandboxSize)
	if err := msg.PutClassAd(ctx, xferInfo); err != nil {
		return fmt.Errorf("failed to send xfer_info ClassAd: %w", err)
	}

	// 3. EOM
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish xfer_info message: %w", err)
	}

	return nil
}
