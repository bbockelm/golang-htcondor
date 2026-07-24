package htcondor

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMasterFromEnvParsesCondorInherit(t *testing.T) {
	original := os.Getenv("CONDOR_INHERIT")
	t.Cleanup(func() { _ = os.Setenv("CONDOR_INHERIT", original) })

	require.NoError(t, os.Setenv("CONDOR_INHERIT", "1234 <127.0.0.1:9618> 0"))

	master, err := MasterFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "<127.0.0.1:9618>", master.Address())
	assert.Equal(t, 1234, master.ParentPID())
}

func TestKeepAliveDefaults(t *testing.T) {
	opts := withKeepAliveDefaults(nil)
	assert.Equal(t, defaultHangTimeout, opts.HangTimeout)
	assert.Equal(t, computeKeepAliveInterval(defaultHangTimeout), opts.Interval)
}

func TestStartKeepAliveLoop(t *testing.T) {
	sender := &fakeMasterSender{}
	master := &Master{address: "<127.0.0.1:9618>", sender: sender}

	opts := &KeepAliveOptions{
		HangTimeout: time.Second,
		Interval:    20 * time.Millisecond,
	}

	stop, errCh, err := master.StartKeepAlive(context.Background(), opts)
	require.NoError(t, err)

	// Poll for at least two keep-alive ticks instead of sleeping a fixed window:
	// on a loaded/slow runner (e.g. emulated CI) ticks can be delayed, so a fixed
	// sleep could observe fewer than expected. Eventually tolerates that jitter.
	require.Eventually(t, func() bool {
		return sender.keepAliveCount() >= 2
	}, 2*time.Second, opts.Interval/2)
	stop()

	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestSendReadyDefaults(t *testing.T) {
	sender := &fakeMasterSender{}
	master := &Master{address: "<127.0.0.1:9618>", daemonName: "mydaemon", sender: sender}

	err := master.SendReady(context.Background(), nil)
	require.NoError(t, err)

	calls := sender.readyCallsSnapshot()
	require.Len(t, calls, 1)
	call := calls[0]
	assert.Equal(t, "mydaemon", call.Name)
	assert.Equal(t, "Ready", call.State)
	assert.Equal(t, os.Getpid(), call.PID)
}

// TestSetDaemonName verifies SendReady reports a name set via SetDaemonName
// (used to supply the subsystem when _CONDOR_DAEMON_NAME is unset, so the
// master does not log an empty "Setting ready state ... for ").
func TestSetDaemonName(t *testing.T) {
	sender := &fakeMasterSender{}
	master := &Master{address: "<127.0.0.1:9618>", sender: sender}
	require.Empty(t, master.DaemonName())

	master.SetDaemonName("HTCONDORDB")
	assert.Equal(t, "HTCONDORDB", master.DaemonName())

	require.NoError(t, master.SendReady(context.Background(), nil))
	calls := sender.readyCallsSnapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "HTCONDORDB", calls[0].Name)
}

type fakeMasterSender struct {
	mu             sync.Mutex
	keepAliveCalls []keepAliveRequest
	readyCalls     []readyRequest
	keepAliveErr   error
	readyErr       error
}

func (f *fakeMasterSender) sendKeepAlive(_ context.Context, req keepAliveRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keepAliveCalls = append(f.keepAliveCalls, req)
	return f.keepAliveErr
}

func (f *fakeMasterSender) sendReady(_ context.Context, req readyRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readyCalls = append(f.readyCalls, req)
	return f.readyErr
}

func (f *fakeMasterSender) keepAliveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keepAliveCalls)
}

func (f *fakeMasterSender) readyCallsSnapshot() []readyRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshot := make([]readyRequest, len(f.readyCalls))
	copy(snapshot, f.readyCalls)
	return snapshot
}
