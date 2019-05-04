package memory

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/raintank/schema"

	"github.com/grafana/metrictank/idx"
	log "github.com/sirupsen/logrus"
)

var (
	errInvalidQuery = errors.New("invalid query")
)

// the supported operators are documented together with the graphite
// reference implementation:
// http://graphite.readthedocs.io/en/latest/tags.html
//
// some of the following operators are non-standard and are only used
// internally to implement certain functionalities requiring them

type match uint16

const (
	EQUAL      match = iota // =
	NOT_EQUAL               // !=
	MATCH                   // =~        regular expression
	MATCH_TAG               // __tag=~   relies on special key __tag. non-standard, required for `/metrics/tags` requests with "filter"
	NOT_MATCH               // !=~
	PREFIX                  // ^=        exact prefix, not regex. non-standard, required for auto complete of tag values
	PREFIX_TAG              // __tag^=   exact prefix with tag. non-standard, required for auto complete of tag keys
)

type expression struct {
	kv
	operator match
}

// a key / value combo used to represent a tag expression like "key=value"
// the cost is an estimate how expensive this query is compared to others
// with the same operator
type kv struct {
	cost  uint // cost of evaluating expression, compared to other kv objects
	key   string
	value string
}

func (k *kv) stringIntoBuilder(builder *strings.Builder) {
	builder.WriteString(k.key)
	builder.WriteString("=")
	builder.WriteString(k.value)
}

// kv expressions that rely on regular expressions will get converted to kvRe in
// NewTagQuery() to accommodate the additional requirements of regex based queries.
type kvRe struct {
	cost           uint // cost of evaluating expression, compared to other kvRe objects
	key            string
	value          *regexp.Regexp // the regexp pattern to evaluate, nil means everything should match
	matchCache     *sync.Map      // needs to be reference so kvRe can be copied, caches regex matches
	matchCacheSize int32          // sync.Map does not have a way to get the length
	missCache      *sync.Map      // needs to be reference so kvRe can be copied, caches regex misses
	missCacheSize  int32          // sync.Map does not have a way to get the length
}

type KvByCost []kv

func (a KvByCost) Len() int           { return len(a) }
func (a KvByCost) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a KvByCost) Less(i, j int) bool { return a[i].cost < a[j].cost }

type KvReByCost []kvRe

func (a KvReByCost) Len() int           { return len(a) }
func (a KvReByCost) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a KvReByCost) Less(i, j int) bool { return a[i].cost < a[j].cost }

type filter struct {
	expr            expression
	test            tagFilter
	defaultDecision filterDecision
	meta            bool
}

// TagQuery runs a set of pattern or string matches on tag keys and values against
// the index. It is executed via:
// Run() which returns a set of matching MetricIDs
// RunGetTags() which returns a list of tags of the matching metrics
type TagQuery struct {
	// clause that operates on LastUpdate field
	from    int64
	filters []filter

	metricExpressions        []expression
	mixedExpressions         []expression
	tagQuery                 expression
	initialExpression        expression
	initialExpressionUseMeta bool

	index       TagIndex                     // the tag index, hierarchy of tags & values, set by Run()/RunGetTags()
	byId        map[schema.MKey]*idx.Archive // the metric index by ID, set by Run()/RunGetTags()
	metaIndex   metaTagIndex
	metaRecords metaTagRecords

	subQuery bool

	wg *sync.WaitGroup
}

func tagQueryFromExpressions(expressions []expression, from int64, subQuery bool) (*TagQuery, error) {
	q := TagQuery{from: from, wg: &sync.WaitGroup{}, subQuery: subQuery}

	// every set of expressions must have at least one positive operator (=, =~, ^=, <tag>!=<empty>, __tag^=, __tag=~)
	foundPositiveOperator := false
	for _, e := range expressions {

		if !foundPositiveOperator && e.isPositiveOperator() {
			foundPositiveOperator = true
		}

		q.mixedExpressions = append(q.mixedExpressions, e)
	}

	if !foundPositiveOperator {
		return nil, errInvalidQuery
	}

	return &q, nil
}

// NewTagQuery initializes a new tag query from the given expressions and the
// from timestamp. It assigns all expressions to the expression group for
// metric tags, later when sortByCost is called it will move those out which
// are keyed by a tag that doesn't exist in the metric index.
func NewTagQuery(expressions []string, from int64) (*TagQuery, error) {
	if len(expressions) == 0 {
		return nil, errInvalidQuery
	}

	parsed := make([]expression, 0, len(expressions))
	sort.Strings(expressions)
	for i, expr := range expressions {
		// skip duplicate expression
		if i > 0 && expr == expressions[i-1] {
			continue
		}

		e, err := parseExpression(expr)
		if err != nil {
			return nil, err
		}

		parsed = append(parsed, e)
	}

	query, err := tagQueryFromExpressions(parsed, from, false)
	if err != nil {
		return nil, err
	}

	return query, nil
}

// Run executes the tag query on the given index and returns a list of ids
func (q *TagQuery) Run() IdSet {
	res := q.run()

	result := make(IdSet)
	for id := range res {
		result[id] = struct{}{}
	}

	return result
}

func (q *TagQuery) run() chan schema.MKey {
	q.sortByCost()

	prepareFiltersWg := sync.WaitGroup{}
	prepareFiltersWg.Add(1)
	go func() {
		defer prepareFiltersWg.Done()
		q.prepareFilters()
	}()

	initialIds := make(chan schema.MKey, 1000)
	q.getInitialIds(initialIds)

	q.wg.Add(TagQueryWorkers)
	results := make(chan schema.MKey, 10000)
	prepareFiltersWg.Wait()

	// start the tag query workers. they'll consume the ids on the idCh and
	// evaluate for each of them whether it satisfies all the conditions
	// defined in the query expressions. those that satisfy all conditions
	// will be pushed into the resCh
	for i := 0; i < TagQueryWorkers; i++ {
		go q.filterIdsFromChan(initialIds, results)
	}

	go func() {
		q.wg.Wait()
		close(results)
	}()

	return results
}

func (q *TagQuery) initForIndex(defById map[schema.MKey]*idx.Archive, idx TagIndex, mti metaTagIndex, mtr metaTagRecords) {
	q.index = idx
	q.byId = defById
	q.metaIndex = mti
	q.metaRecords = mtr
}

func (q *TagQuery) subQueryFromExpressions(expressions []expression) (*TagQuery, error) {
	query, err := tagQueryFromExpressions(expressions, q.from, true)
	if err != nil {
		// this means we've stored a meta record containing invalid queries
		corruptIndex.Inc()
		return nil, err
	}

	query.index = q.index
	query.byId = q.byId
	query.metaIndex = q.metaIndex
	query.metaRecords = q.metaRecords

	return query, nil
}

// getInitialIds asynchronously collects all ID's of the initial result set.  It returns:
// a channel through which the IDs of the initial result set will be sent
// a stop channel, which when closed, will cause it to abort the background worker.
func (q *TagQuery) getInitialIds(idCh chan schema.MKey) chan struct{} {
	stopCh := make(chan struct{})
	q.wg.Add(1)

	if q.initialExpression.matchesTag() {
		go q.getInitialByTag(idCh, stopCh)
	} else {
		go q.getInitialByTagValue(idCh, stopCh)
	}

	return stopCh
}

func (q *TagQuery) getInitialByTagValue(idCh chan schema.MKey, stopCh chan struct{}) {
	key := q.initialExpression.getKey()
	match := q.initialExpression.getMatcher()
	initialIdsWg := sync.WaitGroup{}
	initialIdsWg.Add(1)

	go func() {
		defer initialIdsWg.Done()
	IDS:
		for v, ids := range q.index[key] {
			if !match(v) {
				continue
			}

			for id := range ids {
				select {
				case <-stopCh:
					break IDS
				case idCh <- id:
				}
			}
		}
	}()

	if !q.subQuery && q.initialExpressionUseMeta {
		for v, records := range q.metaIndex[key] {
			if !match(v) {
				continue
			}

			for _, metaRecordId := range records {
				record, ok := q.metaRecords[metaRecordId]
				if !ok {
					corruptIndex.Inc()
					continue
				}

				initialIdsWg.Add(1)
				go func() {
					defer initialIdsWg.Done()

					query, err := q.subQueryFromExpressions(record.queries)
					if err != nil {
						return
					}

					resCh := query.run()
					for id := range resCh {
						idCh <- id
					}
				}()
			}
		}
	}

	go func() {
		defer close(idCh)
		defer q.wg.Done()
		initialIdsWg.Wait()
	}()
}

// getInitialByTagPrefix generates the initial resultset by creating a list of
// metric IDs of which at least one tag starts with the defined prefix
func (q *TagQuery) getInitialByTag(idCh chan schema.MKey, stopCh chan struct{}) {
	match := q.initialExpression.getMatcher()
	initialIdsWg := sync.WaitGroup{}
	initialIdsWg.Add(1)

	go func() {
		defer initialIdsWg.Done()
	TAGS:
		for tag, values := range q.index {
			if !match(tag) {
				continue
			}

			for _, ids := range values {
				for id := range ids {
					select {
					case <-stopCh:
						break TAGS
					case idCh <- id:
					}
				}
			}
		}
	}()

	if !q.subQuery && q.initialExpressionUseMeta {
		for tag, values := range q.metaIndex {
			if !match(tag) {
				continue
			}

			for _, records := range values {
				for _, metaRecordId := range records {
					record, ok := q.metaRecords[metaRecordId]
					if !ok {
						corruptIndex.Inc()
						continue
					}

					initialIdsWg.Add(1)
					go func() {
						defer initialIdsWg.Done()

						query, err := q.subQueryFromExpressions(record.queries)
						if err != nil {
							return
						}

						resCh := query.run()
						for id := range resCh {
							idCh <- id
						}
					}()
				}
			}
		}
	}

	go func() {
		defer close(idCh)
		defer q.wg.Done()
		initialIdsWg.Wait()
	}()
}

// testByAllExpressions takes and id and a MetricDefinition and runs it through
// all required tests in order to decide whether this metric should be part
// of the final result set or not
// in map/reduce terms this is the reduce function
func (q *TagQuery) testByAllExpressions(id schema.MKey, def *idx.Archive, omitTagFilters bool) bool {
	if !q.testByFrom(def) {
		return false
	}

	for _, filter := range q.filters {
		if res := filter.test(def); res == pass {
			continue
		} else if res == fail {
			return false
		}

		metaRecords := q.getMetaRecords(filter.expr)

		for _, record := range metaRecords {
			if record.testByQueries(def) {
				return true
			}
		}

		if filter.defaultDecision != pass {
			return false
		}
	}

	return true
}

func (q *TagQuery) getMetaRecords(expr expression) []metaTagRecord {
	ids := expr.getMetaRecords(q.metaIndex)
	res := make([]metaTagRecord, 0, len(ids))
	for _, id := range ids {
		if record, ok := q.metaRecords[id]; !ok {
			corruptIndex.Inc()
			continue
		} else {
			res = append(res, record)
		}
	}

	return res
}

// testByFrom filters a given metric by its LastUpdate time
func (q *TagQuery) testByFrom(def *idx.Archive) bool {
	return q.from <= atomic.LoadInt64(&def.LastUpdate)
}

// filterIdsFromChan takes a channel of metric ids and runs them through the
// required tests to decide whether a metric should be part of the final
// result set or not
// it returns the final result set via the given resCh parameter
func (q *TagQuery) filterIdsFromChan(idCh, resCh chan schema.MKey) {
	defer q.wg.Done()

	for id := range idCh {
		var def *idx.Archive
		var ok bool

		if def, ok = q.byId[id]; !ok {
			// should never happen because every ID in the tag index
			// must be present in the byId lookup table
			corruptIndex.Inc()
			log.Errorf("memory-idx: ID %q is in tag index but not in the byId lookup table", id)
			continue
		}

		// we always omit tag filters because Run() does not support filtering by tags
		if q.testByAllExpressions(id, def, false) {
			resCh <- id
		}
	}
}

func (q *TagQuery) prepareFilters() {
	q.filters = make([]filter, len(q.metricExpressions)+len(q.mixedExpressions))
	i := 0
	for _, expr := range q.metricExpressions {
		q.filters[i] = filter{
			expr:            expr,
			test:            expr.getFilter(),
			defaultDecision: expr.getDefaultDecision(),
			meta:            false,
		}
		i++
	}
	for _, expr := range q.mixedExpressions {
		q.filters[i] = filter{
			expr:            expr,
			test:            expr.getFilter(),
			defaultDecision: expr.getDefaultDecision(),
			meta:            true,
		}
		i++
	}
	if q.tagQuery != nil && q.tagQuery != q.initialExpression {
		q.filters = append(q.filters, filter{
			expr:            q.tagQuery,
			test:            q.tagQuery.getFilter(),
			defaultDecision: q.tagQuery.getDefaultDecision(),
			meta:            true,
		})
	}
}

func (q *TagQuery) sortByCostWithMeta() {
	var mixedExpressions []expression
	var metricExpressions []expression
	for _, e := range q.mixedExpressions {
		op := e.getOperator()

		// match tag and prefix tag operator expressions always take the meta index
		// into account, unless using the meta index is disabled for this query
		if op == opMatchTag || op == opPrefixTag {
			q.tagQuery = e
		} else {
			if _, ok := q.metaIndex[e.getKey()]; ok {
				mixedExpressions = append(mixedExpressions, e)
			} else {
				metricExpressions = append(metricExpressions, e)
			}
		}
	}

	getCostMultiplier := func(expr expression) int {
		if expr.hasRe() {
			return 10
		}
		return 1
	}

	sort.Slice(metricExpressions, func(i, j int) bool {
		return len(q.index[metricExpressions[i].getKey()])*getCostMultiplier(metricExpressions[i]) < len(q.index[metricExpressions[j].getKey()])*getCostMultiplier(metricExpressions[j])
	})

	sort.Slice(mixedExpressions, func(i, j int) bool {
		return ((len(q.index[mixedExpressions[i].getKey()]) + len(q.metaIndex[mixedExpressions[i].getKey()])) * getCostMultiplier(mixedExpressions[i])) < ((len(q.index[mixedExpressions[j].getKey()]) + len(q.metaIndex[mixedExpressions[j].getKey()])) * getCostMultiplier(mixedExpressions[j]))
	})

	q.metricExpressions = metricExpressions
	q.mixedExpressions = mixedExpressions
}

func (q *TagQuery) sortByCostWithoutMeta() {
	q.metricExpressions = append(q.metricExpressions, q.mixedExpressions...)
	q.mixedExpressions = []expression{}

	// extract tag query if there is one
	for i, e := range q.metricExpressions {
		op := e.getOperator()

		if op == opMatchTag || op == opPrefixTag {
			q.tagQuery = e
			q.metricExpressions = append(q.metricExpressions[:i], q.metricExpressions[i+1:]...)

			// there should never be more than one tag operator
			break
		}
	}

	// We assume that any operation involving a regular expressions is 10 times more expensive than = / !=
	getCostMultiplier := func(expr expression) int {
		if expr.hasRe() {
			return 10
		}
		return 1
	}

	sort.Slice(q.metricExpressions, func(i, j int) bool {
		return len(q.index[q.metricExpressions[i].getKey()])*getCostMultiplier(q.metricExpressions[i]) < len(q.index[q.metricExpressions[j].getKey()])*getCostMultiplier(q.metricExpressions[j])
	})
}

func (q *TagQuery) sortByCost() {
	if q.subQuery {
		q.sortByCostWithoutMeta()
	} else {
		q.sortByCostWithMeta()
	}

	for i, expr := range q.metricExpressions {
		if expr.isPositiveOperator() {
			q.initialExpression = q.metricExpressions[i]
			q.metricExpressions = append(q.metricExpressions[:i], q.metricExpressions[i+1:]...)
			return
		}
	}
	for i, expr := range q.mixedExpressions {
		if expr.isPositiveOperator() {
			q.initialExpression = q.mixedExpressions[i]
			q.mixedExpressions = append(q.mixedExpressions[:i], q.mixedExpressions[i+1:]...)
			q.initialExpressionUseMeta = true
			return
		}
	}
	q.initialExpression = q.tagQuery
}

// getMaxTagCount calculates the maximum number of results (cardinality) a
// tag query could possibly return
// this is useful because when running a tag query we can abort it as soon as
// we know that there can't be more tags discovered and added to the result set
func (q *TagQuery) getMaxTagCount() int {
	defer q.wg.Done()
	var maxTagCount int
	op := q.tagQuery.getOperator()
	match := q.tagQuery.getMatcher()

	if op == opPrefixTag {
		for tag := range q.index {
			if !match(tag) {
				continue
			}
			maxTagCount++
		}
	} else if op == opMatchTag {
		for tag := range q.index {
			if match(tag) {
				maxTagCount++
			}
		}
	} else {
		maxTagCount = len(q.index)
	}

	return maxTagCount
}

// filterTagsFromChan takes a channel of metric IDs and evaluates each of them
// according to the criteria associated with this query
// those that pass all the tests will have their relevant tags extracted, which
// are then pushed into the given tag channel
func (q *TagQuery) filterTagsFromChan(idCh chan schema.MKey, tagCh chan string, stopCh chan struct{}, omitTagFilters bool) {
	defer q.wg.Done()

	// used to prevent that this worker thread will push the same result into
	// the chan twice
	resultsCache := make(map[string]struct{})

	var match func(string) bool
	if q.tagQuery != nil {
		match = q.tagQuery.getMatcher()
	}

IDS:
	for id := range idCh {
		var def *idx.Archive
		var ok bool

		if def, ok = q.byId[id]; !ok {
			// should never happen because every ID in the tag index
			// must be present in the byId lookup table
			corruptIndex.Inc()
			log.Errorf("memory-idx: ID %q is in tag index but not in the byId lookup table", id)
			continue
		}

		// generate a set of all tags of the current metric that satisfy the
		// tag filter condition
		metricTags := make(map[string]struct{}, 0)
		for _, tag := range def.Tags {
			equal := strings.Index(tag, "=")
			if equal < 0 {
				corruptIndex.Inc()
				log.Errorf("memory-idx: ID %q has tag %q in index without '=' sign", id, tag)
				continue
			}

			key := tag[:equal]

			// this tag has already been pushed into tagCh, so we can stop evaluating
			if _, ok := resultsCache[key]; ok {
				continue
			}

			if match != nil {
				// the value doesn't match the requirements
				if !match(key) {
					continue
				}
			}

			// keeping that value as it satisfies all conditions
			metricTags[key] = struct{}{}
		}

		// if we don't filter tags, then we can assume that "name" should always be part of the result set
		if omitTagFilters {
			if _, ok := resultsCache["name"]; !ok {
				metricTags["name"] = struct{}{}
			}
		}

		// if some tags satisfy the current tag filter condition then we run
		// the metric through all tag expression tests in order to decide
		// whether those tags should be part of the final result set
		if len(metricTags) > 0 {
			if q.testByAllExpressions(id, def, omitTagFilters) {
				for key := range metricTags {
					select {
					case tagCh <- key:
					case <-stopCh:
						// if execution of query has stopped because the max tag
						// count has been reached then tagCh <- might block
						// because that channel will not be consumed anymore. in
						// that case the stop channel will have been closed so
						// we so we exit here
						break IDS
					}
					resultsCache[key] = struct{}{}
				}
			} else {
				// check if we need to stop
				select {
				case <-stopCh:
					break IDS
				default:
				}
			}
		}
	}
}

// determines whether the given tag prefix/tag match will match the special
// tag "name". if it does, then we can omit some filtering because we know
// that every metric has a name
func (q *TagQuery) tagFilterMatchesName() bool {
	matchName := false
	op := q.tagQuery.getOperator()

	if op == opPrefixTag || op == opMatchTag {
		match := q.tagQuery.getMatcher()
		if match("name") {
			matchName = true
		}
	}

	return matchName
}

// RunGetTags executes the tag query and returns all the tags of the
// resulting metrics
func (q *TagQuery) RunGetTags() map[string]struct{} {
	maxTagCount := int32(math.MaxInt32)
	matchName := true
	q.sortByCost()

	if q.tagQuery != nil {
		q.wg.Add(1)
		// start a thread to calculate the maximum possible number of tags.
		// this might not always complete before the query execution, but in most
		// cases it likely will. when it does end before the execution of the query,
		// the value of maxTagCount will be used to abort the query execution once
		// the max number of possible tags has been reached
		go atomic.StoreInt32(&maxTagCount, int32(q.getMaxTagCount()))

		// we know there can only be 1 tag filter, so if we detect that the given
		// tag condition matches the special tag "name", we can omit the filtering
		// because every metric has a name.
		matchName = q.tagFilterMatchesName()
	}

	prepareFiltersWg := sync.WaitGroup{}
	prepareFiltersWg.Add(1)
	go func() {
		defer prepareFiltersWg.Done()
		q.prepareFilters()
	}()

	initialIds := make(chan schema.MKey, 1000)
	stopCh := q.getInitialIds(initialIds)
	tagCh := make(chan string)

	prepareFiltersWg.Wait()

	// start the tag query workers. they'll consume the ids on the idCh and
	// evaluate for each of them whether it satisfies all the conditions
	// defined in the query expressions. then they will extract the tags of
	// those that satisfy all conditions and push them into tagCh.
	q.wg.Add(TagQueryWorkers)
	for i := 0; i < TagQueryWorkers; i++ {
		go q.filterTagsFromChan(initialIds, tagCh, stopCh, matchName)
	}

	go func() {
		q.wg.Wait()
		close(tagCh)
	}()

	result := make(map[string]struct{})

	for tag := range tagCh {
		result[tag] = struct{}{}

		// if we know that there can't be more results than what we have
		// abort the query execution
		if int32(len(result)) >= atomic.LoadInt32(&maxTagCount) {
			break
		}
	}

	// abort query execution and wait for all workers to end
	close(stopCh)

	q.wg.Wait()
	return result
}
