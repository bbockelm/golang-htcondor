package spool

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

// Is the mapping worth its complexity? The fan-out has Concurrency
// readers over one buffer, so the question is whether mapping shared
// pages beats pread'ing them per reader.
//
// Run: go test -bench GrowingReaders -benchtime 5x ./spool/
func BenchmarkGrowingReaders(b *testing.B) {
	for _, size := range []int{4 << 20, 64 << 20} {
		payload := bytes.Repeat([]byte("condor"), size/6)
		for _, readers := range []int{1, 10} {
			for _, mode := range []string{"mmap", "pread"} {
				name := fmt.Sprintf("%dMiB/%dreaders/%s", size>>20, readers, mode)
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
								if mode == "pread" {
									rc.(*growingReader).fallback = true
								}
								if _, err := io.Copy(io.Discard, rc); err != nil {
									b.Error(err)
								}
							}()
						}
						wg.Wait()
					}
				})
			}
		}
	}
}
