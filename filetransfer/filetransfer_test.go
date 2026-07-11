// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filetransfer

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/stream"
)

// memSink collects received files in memory.
type memSink struct {
	files map[string][]byte
	modes map[string]int64
	dirs  []string
}

func newMemSink() *memSink {
	return &memSink{files: map[string][]byte{}, modes: map[string]int64{}}
}

func (m *memSink) Mkdir(name string) error {
	m.dirs = append(m.dirs, name)
	return nil
}

type memWriter struct {
	name string
	buf  bytes.Buffer
	sink *memSink
	mode int64
}

func (w *memWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *memWriter) Close() error {
	w.sink.files[w.name] = w.buf.Bytes()
	w.sink.modes[w.name] = w.mode
	return nil
}

func (m *memSink) File(name string, mode int64, _ int64) (io.WriteCloser, error) {
	return &memWriter{name: name, sink: m, mode: mode}, nil
}

// TestSendReceiveRoundTrip drives SendStream and ReceiveStream against each
// other over a net.Pipe and asserts the received bytes match, exercising the
// preamble, go-ahead handshake, per-file framing, mkdir and the TransferAck
// exchange.
func TestSendReceiveRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	sender := stream.NewStream(c1)
	receiver := stream.NewStream(c2)

	payloads := map[string][]byte{
		"input.dat": bytes.Repeat([]byte("abc\n"), 100000), // > one buffer
		"small.txt": []byte("hello world"),
		"empty":     {},
	}
	plan := SendPlan{FinalTransfer: true}
	plan.Files = append(plan.Files, FileSpec{WireName: "sub", Dir: true})
	for _, name := range []string{"input.dat", "small.txt", "empty"} {
		data := payloads[name]
		plan.Files = append(plan.Files, FileSpec{
			WireName: name,
			Mode:     0644,
			Size:     int64(len(data)),
			Open:     func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- SendStream(ctx, sender, plan, Options{Logf: t.Logf, ReceiveAck: false})
	}()

	sink := newMemSink()
	res, err := ReceiveStream(ctx, receiver, sink, Options{Logf: t.Logf, ReceiveAck: true})
	if err != nil {
		t.Fatalf("ReceiveStream: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("SendStream: %v", err)
	}

	if len(res.Files) != 3 {
		t.Errorf("received %d files, want 3: %v", len(res.Files), res.Files)
	}
	if len(sink.dirs) != 1 || sink.dirs[0] != "sub" {
		t.Errorf("dirs = %v, want [sub]", sink.dirs)
	}
	for name, want := range payloads {
		if got, ok := sink.files[name]; !ok {
			t.Errorf("missing file %q", name)
		} else if !bytes.Equal(got, want) {
			t.Errorf("file %q: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}
