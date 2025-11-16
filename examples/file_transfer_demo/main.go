// Package main demonstrates basic file transfer protocol usage.
//
// This example shows how to upload a file using the HTCondor file transfer
// protocol with cedar v0.0.2+ APIs for efficient streaming.
//
// NOTE: This uses the following cedar APIs:
//   - Stream.PutSecret() for secure transfer key transmission
//   - Stream.PutFile() for efficient file streaming
//
// Still missing from CEDAR:
//   - Daemon.StartCommand() (manually send command code instead)
//
// Usage:
//
//	go run examples/file_transfer_demo/main.go <schedd_host> <schedd_port> <file_path>
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func main() {
	// Parse command line arguments
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <schedd_host> <schedd_port> <file_path>\n", os.Args[0])
		fmt.Printf("Example: %s submit.chtc.wisc.edu 9618 /tmp/testfile.txt\n", os.Args[0])
		os.Exit(1)
	}

	scheddHost := os.Args[1]
	scheddPortStr := os.Args[2]
	filePath := os.Args[3]

	scheddPort, err := strconv.Atoi(scheddPortStr)
	if err != nil {
		log.Fatalf("Invalid port: %s", scheddPortStr)
	}

	fmt.Printf("🚀 HTCondor File Transfer Demo\n")
	fmt.Printf("📁 File: %s\n", filePath)
	fmt.Printf("📡 Schedd: %s:%d\n\n", scheddHost, scheddPort)

	// Run the file transfer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := uploadFileDemo(ctx, scheddHost, scheddPort, filePath); err != nil {
		log.Fatalf("❌ Upload failed: %v", err)
	}

	fmt.Printf("✅ Upload completed successfully!\n")
}

// uploadFileDemo demonstrates file upload to HTCondor schedd.
// Uses cedar v0.0.2+ APIs for efficient file transfer.
func uploadFileDemo(ctx context.Context, host string, port int, filePath string) error {
	// Step 1: Get file metadata
	fmt.Printf("📖 Reading file metadata...\n")
	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	fmt.Printf("   File: %s\n", stat.Name())
	fmt.Printf("   Size: %d bytes\n", stat.Size())
	fmt.Printf("   Mode: %o\n", stat.Mode().Perm())

	// Calculate checksum
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}
	checksumStr := fmt.Sprintf("%x", hash.Sum(nil))

	fmt.Printf("   SHA256: %s...\n", checksumStr[:16])

	// Step 2: Connect to schedd using cedar client
	fmt.Printf("\n🔌 Connecting to schedd...\n")
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	htcondorClient, err := client.ConnectToAddress(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to connect to schedd: %w", err)
	}
	defer htcondorClient.Close()

	fmt.Printf("   Connected!\n")

	// Step 3: Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Step 4: Security handshake
	fmt.Printf("\n🔐 Performing security handshake...\n")
	secConfig := &security.SecurityConfig{
		Command:        commands.FILETRANS_UPLOAD,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional, // Allow unauthenticated for testing
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		return fmt.Errorf("security handshake failed: %w", err)
	}

	fmt.Printf("   Authentication: %s\n", negotiation.NegotiatedAuth)
	if negotiation.NegotiatedCrypto != "" {
		fmt.Printf("   Encryption: %s\n", negotiation.NegotiatedCrypto)
	}

	// Step 5: Send FILETRANS_UPLOAD command
	// TODO: This should use StartCommand API when available
	fmt.Printf("\n📤 Sending FILETRANS_UPLOAD command...\n")
	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(commands.FILETRANS_UPLOAD)); err != nil {
		return fmt.Errorf("failed to send command code: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	// Step 6: Send transfer key using Stream.PutSecret()
	// NOTE: In real usage, this would come from job submission
	transKey := fmt.Sprintf("demo-transfer-%d", time.Now().Unix())
	fmt.Printf("\n🔑 Sending transfer key...\n")
	fmt.Printf("   Transfer key: %s\n", transKey)

	if err := cedarStream.PutSecret(ctx, transKey); err != nil {
		return fmt.Errorf("failed to send transfer key: %w", err)
	}

	// Step 7: Send file metadata as ClassAd
	fmt.Printf("\n📋 Sending file metadata...\n")
	metadataAd := classad.New()
	_ = metadataAd.Set("FileName", stat.Name())
	_ = metadataAd.Set("FileSize", stat.Size())
	_ = metadataAd.Set("FileMode", int64(stat.Mode().Perm()))
	_ = metadataAd.Set("ChecksumType", "SHA256")
	_ = metadataAd.Set("Checksum", checksumStr)

	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, metadataAd); err != nil {
		return fmt.Errorf("failed to send metadata ClassAd: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish metadata message: %w", err)
	}

	// Step 8: Send CommandXferFile
	fmt.Printf("\n📦 Streaming file data...\n")
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(htcondor.CommandXferFile)); err != nil {
		return fmt.Errorf("failed to send XferFile command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish XferFile command message: %w", err)
	}

	// Step 9: Stream file data using Stream.PutFile()
	bytesSent, err := cedarStream.PutFile(ctx, filePath)
	if err != nil {
		return fmt.Errorf("failed to send file data: %w", err)
	}

	fmt.Printf("   Streamed %d bytes\n", bytesSent)

	// Step 10: Send CommandFinished
	fmt.Printf("\n✓ Finishing transfer...\n")
	msg = message.NewMessageForStream(cedarStream)
	if err := msg.PutInt32(ctx, int32(htcondor.CommandFinished)); err != nil {
		return fmt.Errorf("failed to send Finished command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish command message: %w", err)
	}

	return nil
}
