package droppriv

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// Wire op codes exchanged between the pool (parent) and its helpers.
const (
	opOpenFile = "openfile"
	opMkdirAll = "mkdirall"
	opChown    = "chown"
	opStat     = "stat"
	opRemove   = "remove"
	opRename   = "rename"
	opCommand  = "command"
	opWait     = "wait"
	opPing     = "ping"
)

// wireRequest is a single RPC from the pool to a helper.
type wireRequest struct {
	Op      string   `json:"op"`
	Path    string   `json:"path,omitempty"`
	NewPath string   `json:"newpath,omitempty"`
	Flag    int      `json:"flag,omitempty"`
	Perm    uint32   `json:"perm,omitempty"`
	UID     int      `json:"uid,omitempty"`
	GID     int      `json:"gid,omitempty"`
	CmdPath string   `json:"cmdpath,omitempty"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Env     []string `json:"env,omitempty"`
	// The following flag which stdio descriptors are attached, in the order
	// stdin, stdout, stderr, as SCM_RIGHTS ancillary data on the request.
	HasStdin  bool `json:"stdin,omitempty"`
	HasStdout bool `json:"stdout,omitempty"`
	HasStderr bool `json:"stderr,omitempty"`
}

// wireResponse is a helper's reply. A successful reply has an empty Err.
type wireResponse struct {
	Err   string    `json:"err,omitempty"`
	Errno int       `json:"errno,omitempty"`
	EOp   string    `json:"eop,omitempty"`
	EPath string    `json:"epath,omitempty"`
	Stat  *wireStat `json:"stat,omitempty"`
	// Command results.
	Pid      int  `json:"pid,omitempty"`
	Signaled bool `json:"signaled,omitempty"`
	Signal   int  `json:"signal,omitempty"`
	ExitCode int  `json:"exitcode,omitempty"`
}

// wireStat is the marshalled form of os.FileInfo.
type wireStat struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
	ModTimeNano int64  `json:"modtime"`
	IsDir       bool   `json:"isdir"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
}

// RemoteStat is returned by the Sys() method of an os.FileInfo produced by a
// pool-backend Stat, exposing the owning uid/gid the helper observed.
type RemoteStat struct {
	UID uint32
	GID uint32
}

// remoteFileInfo implements os.FileInfo over a wireStat.
type remoteFileInfo struct {
	w wireStat
}

func (f *remoteFileInfo) Name() string       { return f.w.Name }
func (f *remoteFileInfo) Size() int64        { return f.w.Size }
func (f *remoteFileInfo) Mode() os.FileMode  { return os.FileMode(f.w.Mode) }
func (f *remoteFileInfo) ModTime() time.Time { return time.Unix(0, f.w.ModTimeNano) }
func (f *remoteFileInfo) IsDir() bool        { return f.w.IsDir }
func (f *remoteFileInfo) Sys() any           { return &RemoteStat{UID: f.w.UID, GID: f.w.GID} }

// statToWire captures an os.FileInfo into its wire form, including uid/gid when
// the platform exposes them via *syscall.Stat_t.
func statToWire(fi os.FileInfo) *wireStat {
	w := &wireStat{
		Name:        fi.Name(),
		Size:        fi.Size(),
		Mode:        uint32(fi.Mode()),
		ModTimeNano: fi.ModTime().UnixNano(),
		IsDir:       fi.IsDir(),
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		w.UID = st.Uid
		w.GID = st.Gid
	}
	return w
}

// errorToWire fills the error fields of a response from err, preserving the
// syscall errno and PathError context so the parent can rebuild an error that
// still satisfies errors.Is(err, os.ErrNotExist) and friends.
func errorToWire(resp *wireResponse, err error) {
	if err == nil {
		return
	}
	resp.Err = err.Error()

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		resp.EOp = pathErr.Op
		resp.EPath = pathErr.Path
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		resp.EOp = linkErr.Op
		resp.EPath = linkErr.Old
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		resp.Errno = int(errno)
	}
}

// wireToError rebuilds an error from a response's error fields.
func wireToError(resp *wireResponse) error {
	if resp.Err == "" && resp.Errno == 0 {
		return nil
	}
	if resp.Errno != 0 {
		//nolint:gosec // G115 - Errno was captured from a real syscall.Errno; the round-trip is within range.
		underlying := syscall.Errno(resp.Errno)
		if resp.EOp != "" || resp.EPath != "" {
			return &os.PathError{Op: resp.EOp, Path: resp.EPath, Err: underlying}
		}
		return underlying
	}
	if resp.Err != "" {
		return errors.New(resp.Err)
	}
	return nil
}

// ensure remoteFileInfo satisfies the interface.
var _ fs.FileInfo = (*remoteFileInfo)(nil)
