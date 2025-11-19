package htcondor

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// TransferCommand represents file transfer protocol commands.
// These match the HTCondor C++ TransferCommand enum from file_transfer.cpp.
type TransferCommand int32

const (
	// CommandFinished indicates transfer complete
	CommandFinished TransferCommand = 0

	// CommandXferFile transfers a file
	CommandXferFile TransferCommand = 1

	// CommandEnableEncryption enables encryption for subsequent transfers
	CommandEnableEncryption TransferCommand = 2

	// CommandDisableEncryption disables encryption for subsequent transfers
	CommandDisableEncryption TransferCommand = 3

	// CommandXferX509 transfers X.509 credential
	CommandXferX509 TransferCommand = 4

	// CommandDownloadURL downloads from URL
	CommandDownloadURL TransferCommand = 5

	// CommandMkdir creates directory
	CommandMkdir TransferCommand = 6

	// CommandOther represents plugin-specific commands
	CommandOther TransferCommand = 999
)

// FileTransferItem represents a single file to transfer.
// Contains metadata needed for the transfer protocol.
type FileTransferItem struct {
	// SrcPath is the source file path (local for upload, remote for download)
	SrcPath string

	// DestPath is the destination file path
	DestPath string

	// FileSize is the size of the file in bytes
	FileSize int64

	// FileMode is the Unix file permissions (e.g., 0644, 0755)
	FileMode uint32

	// Checksum is optional SHA256 checksum for verification
	Checksum string

	// ChecksumType is the type of checksum (e.g., "SHA256")
	ChecksumType string
}

// FileTransferClient handles client-side file transfers.
// Supports uploading files to schedd and downloading from schedd.
type FileTransferClient struct {
	// daemonAddr is the hostname or IP of the daemon (schedd)
	daemonAddr string

	// daemonPort is the port number of the daemon
	daemonPort int

	// transKey is the transfer session key used to identify this transfer
	transKey string
}

// NewFileTransferClient creates a new file transfer client.
func NewFileTransferClient(daemonAddr string, daemonPort int, transKey string) *FileTransferClient {
	return &FileTransferClient{
		daemonAddr: daemonAddr,
		daemonPort: daemonPort,
		transKey:   transKey,
	}
}

// UploadFile uploads a single file to the schedd.
//
// This implements the client side of the FILETRANS_UPLOAD protocol:
//  1. Gather file metadata (size, permissions, checksum)
//  2. Connect to daemon
//  3. Perform security handshake
//  4. Send FILETRANS_UPLOAD command
//  5. Send transfer key (using Stream.PutSecret)
//  6. Send file metadata
//  7. Send CommandXferFile
//  8. Send file data (using Stream.PutFile)
//  9. Send CommandFinished
//
// Parameters:
//   - ctx: Context for cancellation
//   - item: File metadata and paths
//
// Returns error if transfer fails.
//
// NOTE: This implementation uses cedar v0.0.2+ APIs:
//   - Stream.PutSecret() for transfer key transmission
//   - Stream.PutFile() for efficient file streaming
//
// TODO: Still missing Daemon.StartCommand() - currently must manually send command code.
func (ftc *FileTransferClient) UploadFile(ctx context.Context, item FileTransferItem) error {
	// 1. Gather file metadata
	stat, err := os.Stat(item.SrcPath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	item.FileSize = stat.Size()
	item.FileMode = uint32(stat.Mode().Perm())

	// 2. Prepare security config
	addr := fmt.Sprintf("%s:%d", ftc.daemonAddr, ftc.daemonPort)
	secConfig := &security.SecurityConfig{
		Command:        commands.FILETRANS_UPLOAD,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
	}

	// 3. Connect to schedd and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, addr, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect and authenticate to schedd: %w", err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// 4. Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 5. Send FILETRANS_UPLOAD command
	// TODO: Need StartCommand API - for now, manually send command code
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(commands.FILETRANS_UPLOAD)); err != nil {
		return fmt.Errorf("failed to send FILETRANS_UPLOAD command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	// 6. Send transfer key using Stream.PutSecret() (handles encryption automatically)
	if err := cedarStream.PutSecret(ctx, ftc.transKey); err != nil {
		return fmt.Errorf("failed to send transfer key: %w", err)
	}

	// 7. Send file metadata
	if err := ftc.sendFileMetadata(ctx, cedarStream, item); err != nil {
		return fmt.Errorf("failed to send file metadata: %w", err)
	}

	// 8. Send CommandXferFile
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(CommandXferFile)); err != nil {
		return fmt.Errorf("failed to send XferFile command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish XferFile command message: %w", err)
	}

	// 9. Send file data using Stream.PutFile() (efficient streaming)
	bytesSent, err := cedarStream.PutFile(ctx, item.SrcPath)
	if err != nil {
		return fmt.Errorf("failed to send file data: %w", err)
	}
	if bytesSent != item.FileSize {
		return fmt.Errorf("file size mismatch: expected %d bytes, sent %d", item.FileSize, bytesSent)
	}

	// 10. Send CommandFinished
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(CommandFinished)); err != nil {
		return fmt.Errorf("failed to send Finished command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	return nil
}

// DownloadFile downloads a single file from the schedd.
//
// This implements the client side of the FILETRANS_DOWNLOAD protocol:
//  1. Connect to daemon
//  2. Perform security handshake
//  3. Send FILETRANS_DOWNLOAD command
//  4. Send transfer key (using Stream.PutSecret)
//  5. Send file path request
//  6. Receive file metadata
//  7. Receive file data (using Stream.GetFile)
//  8. Verify checksum if provided
//
// Parameters:
//   - ctx: Context for cancellation
//   - remotePath: Path on schedd
//   - localPath: Where to save the file locally
//
// Returns error if transfer fails.
//
// NOTE: This implementation uses cedar v0.0.2+ APIs:
//   - Stream.PutSecret() for transfer key transmission
//   - Stream.GetFile() for efficient file streaming
//
// TODO: Still missing Daemon.StartCommand() - currently must manually send command code.
func (ftc *FileTransferClient) DownloadFile(ctx context.Context, remotePath string, localPath string) error {
	// 1. Prepare security config
	addr := fmt.Sprintf("%s:%d", ftc.daemonAddr, ftc.daemonPort)
	secConfig := &security.SecurityConfig{
		Command:        commands.FILETRANS_DOWNLOAD,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
	}

	// 2. Connect to schedd and authenticate using cedar client
	// This handles session resumption failures automatically
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, addr, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect and authenticate to schedd at %s:%d: %w", ftc.daemonAddr, ftc.daemonPort, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// 3. Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// 4. Send FILETRANS_DOWNLOAD command
	// TODO: Need StartCommand API - for now, manually send command code
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(commands.FILETRANS_DOWNLOAD)); err != nil {
		return fmt.Errorf("failed to send FILETRANS_DOWNLOAD command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	// 5. Send transfer key using Stream.PutSecret() (handles encryption automatically)
	if err := cedarStream.PutSecret(ctx, ftc.transKey); err != nil {
		return fmt.Errorf("failed to send transfer key: %w", err)
	}

	// 6. Send file path request
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutString(ctx, remotePath); err != nil {
		return fmt.Errorf("failed to send remote path: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish path message: %w", err)
	}

	// 7. Receive file metadata (optional, depending on server implementation)
	// For now, we skip metadata reception and go straight to file data
	// In full implementation, we'd receive a ClassAd with file info here

	// 8. Receive file data using Stream.GetFile() (efficient streaming)
	bytesReceived, err := cedarStream.GetFile(ctx, localPath)
	if err != nil {
		return fmt.Errorf("failed to receive file data: %w", err)
	}

	// 9. Verify received (optional - could check against expected size from metadata)
	if bytesReceived == 0 {
		return fmt.Errorf("received empty file")
	}

	// TODO: Verify checksum if provided in metadata
	// TODO: Set file permissions from metadata

	return nil
}

// sendFileMetadata sends file metadata over the stream.
// In the C++ implementation, this can be done via ClassAd or raw protocol.
// For now, we use ClassAd format for flexibility.
func (ftc *FileTransferClient) sendFileMetadata(ctx context.Context, s *stream.Stream, item FileTransferItem) error {
	// Create metadata ClassAd
	metadataAd := classad.New()
	_ = metadataAd.Set("FileName", item.DestPath)
	_ = metadataAd.Set("FileSize", item.FileSize)
	_ = metadataAd.Set("FileMode", int64(item.FileMode))

	if item.Checksum != "" {
		_ = metadataAd.Set("Checksum", item.Checksum)
		_ = metadataAd.Set("ChecksumType", item.ChecksumType)
	}

	// Send ClassAd
	msg := message.NewMessageForStream(s)
	if err := msg.PutClassAd(ctx, metadataAd); err != nil {
		return fmt.Errorf("failed to send metadata ClassAd: %w", err)
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish metadata message: %w", err)
	}

	return nil
}

// receiveFileMetadata receives file metadata from the stream.
//
//nolint:unused // Will be used when implementing file transfer receive operations
func (ftc *FileTransferClient) receiveFileMetadata(ctx context.Context, s *stream.Stream) (*FileTransferItem, error) {
	msg := message.NewMessageFromStream(s)

	ad, err := msg.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive metadata ClassAd: %w", err)
	}

	item := &FileTransferItem{}

	// Extract fields from ClassAd
	if fileName := ad.EvaluateAttr("FileName"); !fileName.IsError() && fileName.IsString() {
		if str, err := fileName.StringValue(); err == nil {
			item.DestPath = str
		}
	}

	if fileSize := ad.EvaluateAttr("FileSize"); !fileSize.IsError() && fileSize.IsInteger() {
		if num, err := fileSize.IntValue(); err == nil {
			item.FileSize = num
		}
	}

	if fileMode := ad.EvaluateAttr("FileMode"); !fileMode.IsError() && fileMode.IsInteger() {
		if num, err := fileMode.IntValue(); err == nil {
			//nolint:gosec // G115: File mode is always in safe range (0-0777)
			item.FileMode = uint32(num)
		}
	}

	if checksum := ad.EvaluateAttr("Checksum"); !checksum.IsError() && checksum.IsString() {
		if str, err := checksum.StringValue(); err == nil {
			item.Checksum = str
		}
	}

	if checksumType := ad.EvaluateAttr("ChecksumType"); !checksumType.IsError() && checksumType.IsString() {
		if str, err := checksumType.StringValue(); err == nil {
			item.ChecksumType = str
		}
	}

	return item, nil
}

// FileTransferServer handles server-side file transfers.
// This would be implemented by schedd to handle incoming transfer requests.
//
// NOTE: Server-side implementation requires command registration API from CEDAR
// which is not yet available. This is a placeholder for future implementation.
type FileTransferServer struct {
	// transKey is the transfer session key
	transKey string

	// baseDir is the base directory for file storage
	baseDir string
}

// NewFileTransferServer creates a new file transfer server handler.
func NewFileTransferServer(transKey string, baseDir string) *FileTransferServer {
	return &FileTransferServer{
		transKey: transKey,
		baseDir:  baseDir,
	}
}

// HandleUpload receives files from a client.
//
// This would be registered as a command handler for FILETRANS_UPLOAD.
// The schedd calls this when a client initiates an upload.
//
// Protocol:
//  1. Receive transfer key (already authenticated)
//  2. Receive file metadata
//  3. Receive file data
//  4. Write to disk
//  5. Wait for CommandFinished
//
// NOTE: Command registration API not yet available in CEDAR Go library.
func (fts *FileTransferServer) HandleUpload(_ context.Context, _ *stream.Stream) error {
	// TODO: Implement server-side upload handling
	return fmt.Errorf("HandleUpload not yet implemented - requires command registration API")

	// PSEUDOCODE:
	// 1. Receive transfer key and verify
	// msg := message.NewMessageFromStream(s)
	// transKey, err := msg.GetString()
	// if err != nil {
	//     return fmt.Errorf("failed to receive transfer key: %w", err)
	// }
	// if transKey != fts.transKey {
	//     return fmt.Errorf("transfer key mismatch")
	// }
	//
	// 2. Receive file metadata
	// metadata, err := fts.receiveFileMetadata(s)
	// if err != nil {
	//     return fmt.Errorf("failed to receive metadata: %w", err)
	// }
	//
	// 3. Receive transfer commands in loop
	// for {
	//     msg = message.NewMessageFromStream(s)
	//     cmd, err := msg.GetInt32()
	//     if err != nil {
	//         return fmt.Errorf("failed to receive command: %w", err)
	//     }
	//
	//     switch TransferCommand(cmd) {
	//     case CommandXferFile:
	//         // Receive file data
	//         data, err := msg.GetBytes(int(metadata.FileSize))
	//         if err != nil {
	//             return fmt.Errorf("failed to receive file data: %w", err)
	//         }
	//
	//         // Write to disk
	//         filePath := filepath.Join(fts.baseDir, metadata.DestPath)
	//         if err := os.WriteFile(filePath, data, os.FileMode(metadata.FileMode)); err != nil {
	//             return fmt.Errorf("failed to write file: %w", err)
	//         }
	//
	//     case CommandFinished:
	//         return nil
	//
	//     default:
	//         return fmt.Errorf("unexpected command: %d", cmd)
	//     }
	// }
}

// HandleDownload sends files to a client.
//
// This would be registered as a command handler for FILETRANS_DOWNLOAD.
// The schedd calls this when a client requests a download.
//
// Protocol:
//  1. Receive transfer key and file request
//  2. Send file metadata
//  3. Send file data
//  4. Send CommandFinished
//
// NOTE: Command registration API not yet available in CEDAR Go library.
func (fts *FileTransferServer) HandleDownload(_ context.Context, _ *stream.Stream) error {
	// TODO: Implement server-side download handling
	return fmt.Errorf("HandleDownload not yet implemented - requires command registration API")
}

// Helper function to receive file metadata (server-side version)
//
//nolint:unused // Will be used when implementing server-side file transfer
func (fts *FileTransferServer) receiveFileMetadata(ctx context.Context, s *stream.Stream) (*FileTransferItem, error) {
	msg := message.NewMessageFromStream(s)

	ad, err := msg.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive metadata ClassAd: %w", err)
	}

	item := &FileTransferItem{}

	// Extract fields from ClassAd (same as client-side)
	if fileName := ad.EvaluateAttr("FileName"); !fileName.IsError() && fileName.IsString() {
		if str, err := fileName.StringValue(); err == nil {
			item.DestPath = str
		}
	}

	if fileSize := ad.EvaluateAttr("FileSize"); !fileSize.IsError() && fileSize.IsInteger() {
		if num, err := fileSize.IntValue(); err == nil {
			item.FileSize = num
		}
	}

	if fileMode := ad.EvaluateAttr("FileMode"); !fileMode.IsError() && fileMode.IsInteger() {
		if num, err := fileMode.IntValue(); err == nil {
			//nolint:gosec // G115: File mode is always in safe range (0-0777)
			item.FileMode = uint32(num)
		}
	}

	return item, nil
}

// Helper function to send file (server-side)
//
//nolint:unused // Will be used when implementing server-side file transfer
func (fts *FileTransferServer) sendFile(ctx context.Context, s *stream.Stream, filePath string) error {
	// Open file
	//nolint:gosec // G304: File path comes from validated transfer request
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", cerr)
		}
	}()

	// Get file info
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Send metadata
	item := FileTransferItem{
		SrcPath:  filePath,
		DestPath: stat.Name(),
		FileSize: stat.Size(),
		FileMode: uint32(stat.Mode().Perm()),
	}

	metadataAd := classad.New()
	_ = metadataAd.Set("FileName", item.DestPath)
	_ = metadataAd.Set("FileSize", item.FileSize)
	_ = metadataAd.Set("FileMode", int64(item.FileMode))

	msg := message.NewMessageForStream(s)
	if err := msg.PutClassAd(ctx, metadataAd); err != nil {
		return fmt.Errorf("failed to send metadata: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish metadata message: %w", err)
	}

	// Send CommandXferFile
	msg = message.NewMessageForStream(s)
	if err := msg.PutInt32(ctx, int32(CommandXferFile)); err != nil {
		return fmt.Errorf("failed to send XferFile command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	// Send file data
	// TODO: This loads entire file to memory - not suitable for large files
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	msg = message.NewMessageForStream(s)
	if err := msg.PutBytes(ctx, data); err != nil {
		return fmt.Errorf("failed to send file data: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish file data message: %w", err)
	}

	// Send CommandFinished
	msg = message.NewMessageForStream(s)
	if err := msg.PutInt32(ctx, int32(CommandFinished)); err != nil {
		return fmt.Errorf("failed to send Finished command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	return nil
}

// GetCommandCodes returns the CEDAR command codes for file transfer operations.
// These are defined in cedar/commands package.
func GetCommandCodes() struct {
	Upload   int
	Download int
} {
	return struct {
		Upload   int
		Download int
	}{
		Upload:   commands.FILETRANS_UPLOAD,
		Download: commands.FILETRANS_DOWNLOAD,
	}
}
