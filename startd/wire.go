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

package startd

import (
	"context"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// claimSinful returns the startd command address embedded at the head of a claim
// id (everything before the first '#'), e.g. "<127.0.0.1:9618?...>". A claim id
// is <sinful>#startd_bday#seq#[session_info]key.
func claimSinful(claimID string) string {
	if i := strings.IndexByte(claimID, '#'); i >= 0 {
		return claimID[:i]
	}
	return ""
}

// writer accumulates the fields of one outgoing CEDAR message and defers the
// first error, so call sites read like the C++ put/put/put chains. The message
// is flushed (with the end-of-message flag) by finish.
type writer struct {
	msg *message.Message
	err error
}

func newWriter(st *stream.Stream) *writer {
	return &writer{msg: message.NewMessageForStream(st)}
}

// putSecret writes a "secret" field. On the encrypted claim session this is
// identical on the wire to a normal string put (an encrypted, length-prefixed
// string); RequestClaim/ReleaseClaim/DeactivateClaim assert encryption before
// using it, so we do not need the stream-level crypto toggle put_secret performs
// on a plaintext stream (which would also force an end-of-message the composed
// claim message must not have).
func (w *writer) putSecret(ctx context.Context, s string) { w.putString(ctx, s) }

func (w *writer) putString(ctx context.Context, s string) {
	if w.err != nil {
		return
	}
	w.err = w.msg.PutString(ctx, s)
}

func (w *writer) putInt(ctx context.Context, v int) {
	if w.err != nil {
		return
	}
	w.err = w.msg.PutInt(ctx, v)
}

func (w *writer) putClassAd(ctx context.Context, ad *classad.ClassAd) {
	if w.err != nil {
		return
	}
	w.err = w.msg.PutClassAd(ctx, ad)
}

// finish flushes the buffered fields as the final frame (end_of_message).
func (w *writer) finish(ctx context.Context) error {
	if w.err != nil {
		return w.err
	}
	w.err = w.msg.FinishMessage(ctx)
	return w.err
}

// reader reads sequential fields from one incoming CEDAR message.
type reader struct {
	msg *message.Message
}

func newReader(st *stream.Stream) *reader {
	return &reader{msg: message.NewMessageFromStream(st)}
}

func (r *reader) getInt(ctx context.Context) (int, error) { return r.msg.GetInt(ctx) }

func (r *reader) getString(ctx context.Context) (string, error) { return r.msg.GetString(ctx) }

func (r *reader) getClassAd(ctx context.Context) (*classad.ClassAd, error) {
	return r.msg.GetClassAd(ctx)
}
