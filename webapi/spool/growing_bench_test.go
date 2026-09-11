package spool

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

// What matters is the read size the consumer uses, not the one a
// benchmark finds convenient. filetransfer.defaultBufferSize is
// 256 KiB (HTCondor's AES_FILE_BUF_SZ), and io.Copy to io.Discard reads
// in 8 KiB chunks -- measuring the latter is how an earlier mmap
// implementation looked 3x faster than the pread it was 2.8x slower
// than on the real path.
//
// Run: go test -run XXX -bench GrowingReaders -benchtime 20x ./spool/
func BenchmarkGrowingReaders(b *testing.B) {
	payload := bytes.Repeat([]byte("condor"), (64<<20)/6)
	for _, bufSize := range []int{8 << 10, 256 << 10} {
		for _, readers := range []int{1, 10} {
			name := fmt.Sprintf("%dKiB/%dreaders", bufSize>>10, readers)
			b.Run(name, func(b *testing.B) {
				g, err := NewGrowing(b.TempDir(), int64(len(payload))+1)
				if err != nil {
					b.Fatal(err)
				}
				defer func() { _ = g.Close() }()
				if err := g.Fill(bytes.NewReader(payload)); err != nil {
					b.Fatal(err)
				}

				b.SetBytes(int64(len(payload)) * int64(readers))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var wg sync.WaitGroup
					for j := 0; j < readers; j++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							rc, err := g.Reader()
							if err != nil {
								b.Error(err)
								return
							}
							defer func() { _ = rc.Close() }()
							buf := make([]byte, bufSize)
							for {
								_, err := rc.Read(buf)
								if err == io.EOF {
									return
								}
								if err != nil {
									b.Error(err)
									return
								}
							}
						}()
					}
					wg.Wait()
				}
			})
		}
	}
}
