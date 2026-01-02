//go:build linux

package droppriv

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// SystemdUserDBLookupStrategy uses systemd-userdbd via varlink protocol.
type SystemdUserDBLookupStrategy struct {
	socketPath string
}

// NewSystemdUserDBLookup creates a new systemd-userdbd lookup strategy.
func NewSystemdUserDBLookup() (*SystemdUserDBLookupStrategy, error) {
	socketPath := "/run/systemd/userdb/io.systemd.UserDatabase"

	// Check if socket exists
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("systemd-userdbd socket not available: %w", err)
	}

	return &SystemdUserDBLookupStrategy{socketPath: socketPath}, nil
}

// varlinkRequest represents a varlink method call.
type varlinkRequest struct {
	Method     string                 `json:"method"`
	Parameters map[string]interface{} `json:"parameters"`
}

// varlinkResponse represents a varlink method response.
type varlinkResponse struct {
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// LookupUser looks up a user using systemd-userdbd varlink protocol.
func (s *SystemdUserDBLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", s.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to systemd-userdbd: %w", err)
	}
	defer func() {
		_ = conn.Close() // Ignore error - connection is being closed anyway
	}()

	// Send GetUserRecord request
	request := varlinkRequest{
		Method: "io.systemd.UserDatabase.GetUserRecord",
		Parameters: map[string]interface{}{
			"userName": username,
		},
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(request); err != nil {
		return nil, fmt.Errorf("failed to send varlink request: %w", err)
	}

	// Read response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read varlink response: %w", err)
		}
		return nil, fmt.Errorf("empty varlink response")
	}

	var response varlinkResponse
	if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("failed to parse varlink response: %w", err)
	}

	if response.Error != "" {
		if response.Error == "io.systemd.UserDatabase.NoRecordFound" {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("varlink error: %s", response.Error)
	}

	// Parse user record (JSON User Record format)
	record, ok := response.Parameters["record"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid user record in response")
	}

	uid, _ := record["uid"].(float64)
	gid, _ := record["gid"].(float64)
	homeDir, _ := record["homeDirectory"].(string)
	shell, _ := record["shell"].(string)

	// Try to get group name
	groupname := fmt.Sprintf("%d", uint32(gid))

	return &UserInfo{
		UID:       uint32(uid),
		GID:       uint32(gid),
		Username:  username,
		Groupname: groupname,
		HomeDir:   homeDir,
		Shell:     shell,
	}, nil
}

// Name returns the strategy name.
func (s *SystemdUserDBLookupStrategy) Name() string {
	return "systemd-userdbd-varlink"
}

// trySystemdUserDB attempts to create a systemd-userdbd lookup strategy.
//
//nolint:unused // infrastructure function, may be used in future implementations
func trySystemdUserDB() (LookupStrategy, error) {
	return NewSystemdUserDBLookup()
}
