// package chunk encodes timeseries in chunks of data
// see devdocs/chunk-format.md for more information.
package chunk

import (
	"fmt"

	"github.com/grafana/metrictank/mdata/chunk/tsz"
)

// Chunk is a chunk of data. not concurrency safe.
type Chunk struct {
	tsz.SeriesLong
	NumPoints uint32
	First     bool
}

func New(t0 uint32) *Chunk {
	return &Chunk{
		SeriesLong: *tsz.NewSeriesLong(t0),
	}
}

func NewFirst(t0 uint32) *Chunk {
	return &Chunk{
		SeriesLong: *tsz.NewSeriesLong(t0),
		First:      true,
	}
}

func (c *Chunk) String() string {
	return fmt.Sprintf("<chunk T0=%d, LastTs=%d, NumPoints=%d, First=%t, Closed=%t>", c.T0, c.T, c.NumPoints, c.First, c.Finished)
}

func (c *Chunk) Push(t uint32, v float64) error {
	if t <= c.T {
		return fmt.Errorf("Point must be newer than already added points. t:%d lastTs: %d", t, c.T)
	}
	c.SeriesLong.Push(t, v)
	c.NumPoints += 1
	return nil
}

func (c *Chunk) Finish() {
	c.SeriesLong.Finish()
}

// Encode encodes the chunk
// note: chunks don't know their own span, the caller/owner manages that,
// so for formats that encode it, it needs to be passed in.
func (c *Chunk) Encode(span uint32) []byte {
	return encode(span, FormatGoTszLongWithSpan, c.SeriesLong.Bytes())
}
