package idx

import (
	"github.com/grafana/metrictank/stats"
)

var (
	// metric recovered_errors.idx.memory.invalid-tag is how many times
	// an invalid tag for a metric is encountered.
	// each time this happens, an error is logged with more details.
	invalidTag = stats.NewCounter32("recovered_errors.idx.memory.invalid-tag")

	// metric recovered_errors.idx.memory.intern-error is how many times
	// an error is encountered while attempting to intern a string.
	// each time this happens, an error is logged with more details.
	internError = stats.NewCounter32("recovered_errors.idx.memory.intern-error")
)
