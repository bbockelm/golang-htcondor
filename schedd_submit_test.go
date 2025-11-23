package htcondor

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestScheddSubmitIntegration tests job submission to a real schedd
func TestScheddSubmitIntegration(t *testing.T) {
	// Check if condor_master is available
	masterPath, err := exec.LookPath("condor_master")
	if err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	t.Logf("Found condor_master at: %s", masterPath)

	// Set up mini HTCondor environment
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	ctx := context.Background()

	// Use LocateDaemon to discover schedd
	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	t.Logf("Schedd discovered: name=%s, address=%s", location.Name, location.Address)

	// Test 1: Create a simple job ClassAd
	t.Run("SubmitSimpleJob", func(t *testing.T) {
		ctx := context.Background()

		// Create a simple job ad
		jobAd := classad.New()
		_ = jobAd.Set("Cmd", "/bin/sleep")
		_ = jobAd.Set("Args", "60")
		_ = jobAd.Set("Universe", 5) // Vanilla
		// Owner is set via SetEffectiveOwner, not as a job attribute
		_ = jobAd.Set("JobStatus", 1) // Idle
		_ = jobAd.Set("RequestCpus", 1)
		_ = jobAd.Set("RequestMemory", 128)
		_ = jobAd.Set("RequestDisk", 1024)

		// Connect to schedd's queue management interface
		// Note: NewQmgmtConnection calls GetCapabilities which implicitly starts a transaction
		qmgmt, err := NewQmgmtConnection(ctx, location.Address)
		if err != nil {
			harness.PrintScheddLog()
			t.Fatalf("Failed to connect to schedd: %v", err)
		}
		defer func() {
			if cerr := qmgmt.Close(); cerr != nil {
				t.Logf("Warning: failed to close qmgmt connection: %v", cerr)
			}
		}()

		// Transaction is already started by GetCapabilities, no need to call BeginTransaction

		// Set effective owner - this must be done before creating jobs
		// For FS authentication, we must use the authenticated username
		// We can't set arbitrary owners unless we're a superuser
		owner := qmgmt.authenticatedUser
		if owner == "" {
			harness.PrintScheddLog()
			_ = qmgmt.AbortTransaction(ctx)
			t.Fatal("No authenticated user from QMGMT connection")
		}
		if err := qmgmt.SetEffectiveOwner(ctx, owner); err != nil {
			harness.PrintScheddLog()
			_ = qmgmt.AbortTransaction(ctx)
			t.Fatalf("Failed to set effective owner: %v", err)
		}

		t.Logf("Set effective owner to: %s", owner)

		// Create new cluster
		clusterID, err := qmgmt.NewCluster(ctx)
		if err != nil {
			_ = qmgmt.AbortTransaction(ctx)
			t.Fatalf("Failed to create new cluster: %v", err)
		}

		t.Logf("Created cluster ID: %d", clusterID)

		// Create new proc
		procID, err := qmgmt.NewProc(ctx, clusterID)
		if err != nil {
			_ = qmgmt.AbortTransaction(ctx)
			t.Fatalf("Failed to create new proc: %v", err)
		}

		t.Logf("Created proc ID: %d", procID)

		// Send all job attributes (Owner will be set automatically based on SetEffectiveOwner)
		if err := qmgmt.SendJobAttributes(ctx, clusterID, procID, jobAd); err != nil {
			_ = qmgmt.AbortTransaction(ctx)
			t.Fatalf("Failed to send job attributes: %v", err)
		}

		// Commit transaction
		if err := qmgmt.CommitTransaction(ctx); err != nil {
			_ = qmgmt.AbortTransaction(ctx)
			t.Fatalf("Failed to commit transaction: %v", err)
		}

		t.Logf("Successfully submitted job %d.%d", clusterID, procID)
	})
}

// parseCollectorSinfulString extracts host:port from HTCondor sinful string format
// HTCondor uses format: <host:port?addrs=host-port&alias=hostname>
func parseCollectorSinfulString(addr string) string {
	// Remove angle brackets
	addr = strings.TrimPrefix(addr, "<")

	// Split on ? to remove query parameters
	if idx := strings.Index(addr, "?"); idx > 0 {
		addr = addr[:idx]
	}

	// Remove trailing >
	addr = strings.TrimSuffix(addr, ">")

	return addr
}

// Integration Test Design Notes:
//
// This integration test demonstrates the structure for job submission testing.
// It's currently skipped due to missing authentication infrastructure.
//
// Required implementations before enabling this test:
//
// 1. CEDAR Protocol Integration:
//    - ReliSock implementation for persistent connections
//    - Message framing and encoding/decoding
//    - Command sending and response parsing
//
// 2. Security/Authentication:
//    - DC_AUTHENTICATE handshake implementation
//    - Support for at least one auth method (FS_REMOTE, SSL, or TOKEN)
//    - For integration tests, FS_REMOTE is simplest (no credentials needed)
//    - Session establishment and encryption setup
//
// 3. QMGMT Protocol:
//    - QMGMT_WRITE_CMD (1112) to enter queue management mode
//    - CONDOR_BeginTransaction (500)
//    - CONDOR_NewCluster (500)
//    - CONDOR_NewProc (501)
//    - CONDOR_SetAttribute (503) or CONDOR_SetAttributeWithFlags (519)
//    - CONDOR_CommitTransactionNoFlags (507)
//    - CONDOR_CloseSocket (509)
//
// 4. Test Infrastructure Updates:
//    - Update CondorTestHarness to track schedd address (similar to collector)
//    - Add methods to get schedd address from harness
//    - Ensure schedd is fully initialized before attempting connections
//
// Wire Protocol Reference:
//
// Each QMGMT command follows this format:
//   [Command ID: int32]
//   [Parameters: varies by command]
//   [End of Message marker]
//
// Response format:
//   [Status Code: int32]  // 0 = success, negative = error
//   [Error Code: int32]   // if status < 0
//   [Result Data: varies] // if status >= 0
//   [End of Message marker]
//
// Example flow for submitting one job:
//
//   Client -> Schedd: CONDOR_BeginTransaction
//   Schedd -> Client: status=0
//
//   Client -> Schedd: CONDOR_NewCluster
//   Schedd -> Client: status=ClusterID (e.g., 1001)
//
//   Client -> Schedd: CONDOR_NewProc(1001)
//   Schedd -> Client: status=ProcID (e.g., 0)
//
//   Client -> Schedd: CONDOR_SetAttribute(1001, 0, "Cmd", "/bin/sleep")
//   Schedd -> Client: status=0
//
//   Client -> Schedd: CONDOR_SetAttribute(1001, 0, "Args", "60")
//   Schedd -> Client: status=0
//
//   [... more attributes ...]
//
//   Client -> Schedd: CONDOR_CommitTransactionNoFlags
//   Schedd -> Client: status=0
//
// Comparison with Collector Query Protocol:
//
// The schedd submit protocol is significantly different from collector queries:
//
// - Collector: Stateless, single request-response, no transactions
// - Schedd: Stateful, multi-command session, requires transactions
// - Collector: Sends complete ClassAd in query
// - Schedd: Sends attributes one-by-one via SetAttribute
// - Collector: No authentication required for basic queries
// - Schedd: Always requires authentication for queue management
// - Collector: Uses query commands (QUERY_STARTD_ADS, etc.)
// - Schedd: Uses QMGMT protocol commands
//
// Priority for Implementation:
//
// 1. HIGH: FS_REMOTE authentication (simplest, no tokens/certs needed)
// 2. HIGH: Basic QMGMT protocol (Begin/Commit/NewCluster/NewProc/SetAttribute)
// 3. MEDIUM: ReliSock implementation for persistent connections
// 4. MEDIUM: SetAttribute batching and NoAck flag for performance
// 5. LOW: Advanced features (late materialization, jobsets, etc.)
