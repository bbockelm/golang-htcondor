package utilization

import (
	"runtime"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Decoder turns history records into Jobs on several cores while they
// are still being read.
//
// Reading a history record costs far more than analysing it: parsing
// one old-ClassAd row with the full projection is about 40 microseconds,
// FromAd another 9 (BenchmarkRealisticParse, BenchmarkRealisticFromAd),
// against about one for its share of Analyze. A million of them on the
// one goroutine that also reads the stream is most of a minute; spread
// over the cores while the stream is still arriving, the read is the
// only thing left to wait for.
//
// Records go to the workers in batches, so the channel costs nothing
// per record, and each worker keeps its own JobReader, so interning
// needs no lock. The Jobs come back in no particular order; nothing in
// the analysis depends on it.
type Decoder struct {
	work    chan []decodeItem
	batch   []decodeItem
	wg      sync.WaitGroup
	results [][]Job
	busy    []time.Duration
}

type decodeItem struct {
	text   string
	ad     *classad.ClassAd
	schedd string
}

// decodeBatch is how many records go to a worker at once.
const decodeBatch = 256

// NewDecoder starts workers decoders; zero or less means one per core.
func NewDecoder(workers int) *Decoder {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	d := &Decoder{
		work:    make(chan []decodeItem, 2*workers),
		results: make([][]Job, workers),
		busy:    make([]time.Duration, workers),
		batch:   make([]decodeItem, 0, decodeBatch),
	}
	for w := range workers {
		d.wg.Add(1)
		go d.run(w)
	}
	return d
}

func (d *Decoder) run(w int) {
	defer d.wg.Done()
	var reader JobReader
	for items := range d.work {
		start := time.Now()
		for _, it := range items {
			ad := it.ad
			if ad == nil {
				parsed, err := classad.ParseOld(it.text)
				if err != nil {
					continue // an unparseable record costs one sample
				}
				ad = parsed
			}
			d.results[w] = append(d.results[w], reader.FromAd(ad, it.schedd))
		}
		d.busy[w] += time.Since(start)
	}
}

// Row queues an old-ClassAd text record.
func (d *Decoder) Row(text string) { d.add(decodeItem{text: text}) }

// Ad queues a record already parsed.
func (d *Decoder) Ad(ad *classad.ClassAd, schedd string) { d.add(decodeItem{ad: ad, schedd: schedd}) }

func (d *Decoder) add(it decodeItem) {
	d.batch = append(d.batch, it)
	if len(d.batch) == decodeBatch {
		d.work <- d.batch
		d.batch = make([]decodeItem, 0, decodeBatch)
	}
}

// Finish waits for every queued record and returns the Jobs, one slice
// per worker (see AnalyzeChunks: copying a million Jobs into one slice
// would double the memory an analysis needs at its peak), and the time
// the workers spent decoding, summed across them. The Decoder may not be
// used again.
func (d *Decoder) Finish() ([][]Job, time.Duration) {
	if len(d.batch) > 0 {
		d.work <- d.batch
		d.batch = nil
	}
	close(d.work)
	d.wg.Wait()
	var busy time.Duration
	chunks := make([][]Job, 0, len(d.results))
	for w := range d.results {
		busy += d.busy[w]
		if len(d.results[w]) > 0 {
			chunks = append(chunks, d.results[w])
		}
	}
	return chunks, busy
}

// Count is how many Jobs chunks hold.
func Count(chunks [][]Job) int {
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	return n
}
