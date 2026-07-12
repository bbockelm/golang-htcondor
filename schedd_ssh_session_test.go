package htcondor

import (
	"fmt"
	"testing"

	"github.com/bbockelm/cedar/security"
)

// TestStarterSessionAdvertisesAES is a regression test for the condor_ssh_to_job
// (START_SSHD) break: the schedd builds an inherited AES-GCM session from the
// claim GET_JOB_CONNECT_INFO returns and resumes it to send the encrypted
// START_SSHD request to the starter.
//
// HTCondor's ExportSecSessionInfo emits, for back-compat, a *legacy* single
// CryptoMethods field holding an old-preferred cipher (e.g. BLOWFISH via
// getPreferredOldCryptProtocol) alongside the modern CryptoMethodsList whose
// head is AES. The session key is always derived for AES-GCM (cedar implements
// only that), so the session policy MUST advertise AES too. If it instead
// carries the legacy BLOWFISH, the schedd encrypts with AES-GCM but tells the
// starter the cipher is BLOWFISH; the starter decrypts garbage and START_SSHD
// fails with "FAILED to get number of expressions".
//
// (A refactor that delegated buildAESStarterSession to cedar's
// CreateNonNegotiatedSession regressed this: that helper copied the legacy
// CryptoMethods verbatim. This test fails against that behavior and passes with
// the manual construction that pins CryptoMethods=AES.)
func TestStarterSessionAdvertisesAES(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// session info exactly as a modern schedd exports it: legacy CryptoMethods
	// is a non-AES old-preferred cipher; the modern list leads with AES.
	info := `[Encryption="YES";Integrity="YES";CryptoMethods="BLOWFISH";CryptoMethodsList="AES.BLOWFISH.3DES"]`
	claim := security.ParseClaimIDStrict(fmt.Sprintf("<127.0.0.1:9999>#100#1#%s%s", info, key))

	entry, err := buildAESStarterSession(claim, "<127.0.0.1:9999>")
	if err != nil {
		t.Fatalf("buildAESStarterSession: %v", err)
	}

	// The derived key must be 32 bytes (AES-256-GCM).
	if got := len(entry.KeyInfo().Data); got != 32 {
		t.Errorf("session key length = %d, want 32", got)
	}

	// The advertised cipher must be AES-GCM, never the legacy back-compat value.
	cm, _ := entry.Policy().EvaluateAttrString("CryptoMethods")
	if cm != "AES" && cm != "AESGCM" {
		t.Errorf("session policy CryptoMethods = %q, want AES/AESGCM; a non-AES value tells the starter the wrong cipher and breaks START_SSHD decryption", cm)
	}
}
