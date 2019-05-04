package memory

import (
	"fmt"
	"hash"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/grafana/metrictank/idx"
)

// the collision avoidance window defines how many times we try to find a higher
// slot that's free if two record hashes collide
const collisionAvoidanceWindow = 3

// the function we use to get the hash for hashing the meta records
var queryHash func() hash.Hash32

func init() {
	// can be replaced for mocking in tests
	queryHash = fnv.New32a
}

type metaRecordFilter func(map[string]string) bool

type metaTagRecord struct {
	metaTags     []kv
	queries      []expression
	filterByTags metaRecordFilter
}

// list of meta records keyed by random unique identifier
// key needs to be somehow generated, could be a completely random number
type metaTagRecords map[uint32]metaTagRecord

// index structure keyed by key -> value -> meta record
type metaTagValue map[string][]uint32
type metaTagIndex map[string]metaTagValue

func (m metaTagIndex) deleteRecord(keyValue kv, hash uint32) {
	if values, ok := m[keyValue.key]; ok {
		if hashes, ok := values[keyValue.value]; ok {
			for i := 0; i < len(hashes); i++ {
				if hashes[i] == hash {
					// no need to keep the order
					hashes[i] = hashes[len(hashes)-1]
					values[keyValue.value] = hashes[:len(hashes)-1]
					return
				}
			}
		}
	}
}

func (m metaTagIndex) insertRecord(keyValue kv, hash uint32) {
	var values metaTagValue
	var ok bool

	if values, ok = m[keyValue.key]; !ok {
		values = make(metaTagValue)
		m[keyValue.key] = values
	}

	values[keyValue.value] = append(values[keyValue.value], hash)
}

// newMetaTagRecord takes two slices of strings, parses them and returns a metaTagRecord
// The first slice of strings are the meta tags & values
// The second slice is the tag query expressions which the meta key & values refer to
// On parsing error the second returned value is an error, otherwise it is nil
func newMetaTagRecord(metaTags []string, tagQueryExpressions []string) (metaTagRecord, error) {
	record := metaTagRecord{
		metaTags: make([]kv, 0, len(metaTags)),
		queries:  make([]expression, 0, len(tagQueryExpressions)),
	}
	if len(tagQueryExpressions) == 0 {
		return record, fmt.Errorf("Requiring at least one tag query expression, 0 given")
	}

	for _, tag := range metaTags {
		tagSplits := strings.SplitN(tag, "=", 2)
		if len(tagSplits) < 2 {
			return record, fmt.Errorf("Missing \"=\" sign in tag %s", tag)
		}

		record.metaTags = append(record.metaTags, kv{key: tagSplits[0], value: tagSplits[1]})
	}

	haveTagOperator := false
	for _, query := range tagQueryExpressions {
		parsed, err := parseExpression(query)
		if err != nil {
			return record, err
		}
		if parsed.isTagQueryOperator() {
			if haveTagOperator {
				return record, fmt.Errorf("Only one tag operator is allowed per query")
			}
			haveTagOperator = true
		}
		record.queries = append(record.queries, parsed)
	}

	record.buildMetaRecordFilter()

	return record, nil
}

func (m *metaTagRecord) metaTagStrings(builder *strings.Builder) []string {
	res := make([]string, len(m.metaTags))

	for i, tag := range m.metaTags {
		tag.stringIntoBuilder(builder)
		res[i] = builder.String()
		builder.Reset()
	}

	return res
}

func (m *metaTagRecord) queryStrings(builder *strings.Builder) []string {
	res := make([]string, len(m.queries))

	for i, query := range m.queries {
		query.stringIntoBuilder(builder)
		res[i] = builder.String()
		builder.Reset()
	}

	return res
}

// hashQueries generates a hash of all the queries in the record
func (m *metaTagRecord) hashQueries() uint32 {
	builder := strings.Builder{}
	for i, query := range m.queries {
		if i > 0 {
			builder.WriteString(";")
		}
		query.stringIntoBuilder(&builder)
	}
	h := queryHash()
	h.Write([]byte(builder.String()))
	return h.Sum32()
}

// sortQueries sorts all the queries first by key, then by value, then by
// operator. The order doesn't matter, it only needs to be consistent
func (m *metaTagRecord) sortQueries() {
	sort.Slice(m.queries, func(i, j int) bool {
		if m.queries[i].key == m.queries[j].key {
			if m.queries[i].value == m.queries[j].value {
				return m.queries[i].operator < m.queries[j].operator
			}
			return m.queries[i].value < m.queries[j].value
		}
		return m.queries[i].key < m.queries[j].key
	})
}

// matchesQueries compares another tag record's queries to this
// one's queries. Returns true if they are equal, otherwise false.
// It is assumed that all the queries are already sorted
func (m *metaTagRecord) matchesQueries(other metaTagRecord) bool {
	if len(m.queries) != len(other.queries) {
		return false
	}

	m.sortQueries()
	other.sortQueries()

	for id, query := range m.queries {
		if query.key != other.queries[id].key {
			return false
		}

		if query.operator != other.queries[id].operator {
			return false
		}

		if query.value != other.queries[id].value {
			return false
		}
	}

	return true
}

// hasMetaTags returns true if the meta tag record has one or more
// meta tags, otherwise it returns false
func (m *metaTagRecord) hasMetaTags() bool {
	return len(m.metaTags) > 0
}

// buildMetaRecordFilter builds a function to which a set of tags&values can be passed,
// it then evaluate whether the queries of this meta tag record all match with the given tags
// this is used for the series enrichment
func (m *metaTagRecord) buildMetaRecordFilter() {
	queries := make([]expression, len(m.queries))
	copy(queries, m.queries)

	// we want to sort the queries so the regexes come last, because they are more expensive
	sort.Slice(queries, func(i, j int) bool {
		iHasRe := queries[i].hasRe()
		jHasRe := queries[j].hasRe()

		// when both have a regex or both have no regex, they are considered equal
		if iHasRe == jHasRe {
			return false
		}

		// if i has no regex, but j has one, i is considered cheaper
		if iHasRe == false {
			return true
		}

		// if j has no regex, but i has one, then j is considered cheaper
		return false
	})

	// generate all the filter functions for each of the queries
	filters := make([]func(string, string) bool, 0, len(queries))
	for _, query := range queries {
		matcher := query.getMatcher()
		if query.matchesTag() {
			filters = append(filters, func(tag, value string) bool {
				return matcher(tag)
			})
			continue
		}
		queryKey := query.getKey()
		filters = append(filters, func(tag, value string) bool {
			if tag != queryKey {
				return false
			}
			return matcher(value)
		})
	}

	// generate one function which applies all filters to the given set of tags & values
	m.filterByTags = func(tags map[string]string) bool {
	FILTERS:
		for _, filter := range filters {
			for tag, value := range tags {
				if filter(tag, value) {
					// if one tag/value satisfies the filter we can move on to the next filer
					continue FILTERS
				}
			}

			// if we checked all tag/value pairs, but none satisfied the filter, return false
			return false
		}
		return true
	}
}

// a metaRecordEvaluator is a function that takes a metric definition, looks
// at its metric tags, and then decides whether the given metric should be
// tagged with this meta tag or not. It returns a bool
type metaRecordEvaluator func(*idx.Archive) bool

// getEvaluator returns a metaRecordEvaluator for this meta record
func (m *metaTagRecord) getEvaluator() metaRecordEvaluator {
	filters := make([]tagFilter, len(m.queries))
	defaultDecisions := make([]filterDecision, len(m.queries))
	for i, query := range m.queries {
		filters[i] = query.getFilter()
		defaultDecisions[i] = query.getDefaultDecision()
	}

	return func(def *idx.Archive) bool {
		for i, filter := range filters {
			decision := filter(def)
			if decision == fail || (decision == none && defaultDecisions[i] == fail) {
				return false
			}
		}

		return true
	}
}

// upsert inserts or updates a meta tag record according to the given specifications
// it uses the set of tag query expressions as the identity of the record, if a record with the
// same identity is already present then its meta tags get updated to the specified ones.
// If the new record contains no meta tags, then the update is equivalent to a delete.
// Those are the return values:
// 1) The id at which the new record got inserted
// 2) Pointer to the inserted metaTagRecord
// 3) The id of the record that has been replaced if an update was performed
// 4) Pointer to the metaTagRecord that has been replaced if an update was performed, otherwise nil
// 5) Error if an error occurred, otherwise it's nil
func (m metaTagRecords) upsert(metaTags []string, metricTagQueryExpressions []string) (uint32, *metaTagRecord, uint32, *metaTagRecord, error) {
	record, err := newMetaTagRecord(metaTags, metricTagQueryExpressions)
	if err != nil {
		return 0, nil, 0, nil, err
	}

	record.sortQueries()
	hash := record.hashQueries()
	var oldRecord *metaTagRecord
	var oldHash uint32

	// loop over existing records, starting from hash, trying to find one that has
	// the exact same queries as the one we're inserting
	for i := uint32(0); i < collisionAvoidanceWindow; i++ {
		if existingRecord, ok := m[hash+i]; ok {
			if record.matchesQueries(existingRecord) {
				oldRecord = &existingRecord
				oldHash = hash + i
				break
			}
		}
	}

	// now find the best position to insert the new/updated record, starting from hash
	for i := uint32(0); i < collisionAvoidanceWindow; i++ {
		// if we find a free slot, then insert the new record there
		if _, ok := m[hash]; !ok {
			// add the new record, as long as it has meta tags
			if record.hasMetaTags() {
				m[hash] = record
			}

			// if we're updating a record, then we need to delete the old entry
			if oldRecord != nil {
				delete(m, oldHash)
			}

			return hash, &record, oldHash, oldRecord, nil
		}

		// replace existing old record with the new one, at the same hash id
		if oldRecord != nil && oldHash == hash {
			if record.hasMetaTags() {
				m[hash] = record
			} else {
				// if the new record has no meta tags, then we simply delete the entry
				delete(m, hash)
			}
			return hash, &record, oldHash, oldRecord, nil
		}
		hash++
	}

	return 0, nil, 0, nil, fmt.Errorf("MetaTagRecordUpsert: Unable to find a slot to insert record")
}

func (m metaTagRecords) getRecords(ids []uint32) []metaTagRecord {
	res := make([]metaTagRecord, 0, len(ids))

	for _, id := range ids {
		if record, ok := m[id]; ok {
			res = append(res, record)
		}
	}

	return res
}

func (m metaTagRecords) enrichTags(tags map[string]string) map[string]string {
	res := make(map[string]string)
	for _, mtr := range m {
		if mtr.filterByTags(tags) {
			for _, kv := range mtr.metaTags {
				res[kv.key] = kv.value
			}
		}
	}

	return res
}
