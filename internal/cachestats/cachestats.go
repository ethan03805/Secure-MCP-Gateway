// Package cachestats counts the lookups of the Gateway's in-process caches
// so that the Data Server & Memory view (G-08, FR-8.16) can show their hit
// ratios. A cache registers a Counter once and records each lookup as a hit
// or a miss; Snapshot reports every registered counter. The counts start at
// zero when the process starts.
package cachestats

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Counter counts the lookups of one cache.
type Counter struct {
	name, desc string
	hits       atomic.Int64
	misses     atomic.Int64
	entries    func() int
}

// Hit records a lookup answered from the cache.
func (c *Counter) Hit() { c.hits.Add(1) }

// Miss records a lookup the cache could not answer.
func (c *Counter) Miss() { c.misses.Add(1) }

// Stat is one cache's counts. Ratio is hits / (hits + misses), or null
// before the first lookup.
type Stat struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Hits        int64    `json:"hits"`
	Misses      int64    `json:"misses"`
	Ratio       *float64 `json:"hit_ratio"`
	Entries     *int     `json:"entries,omitempty"`
}

var (
	mu       sync.Mutex
	counters = map[string]*Counter{}
)

// Register returns the counter named name, creating it on first use with
// the description desc. entries, when not nil, reports the number of
// entries the cache holds; it must not call back into this package.
func Register(name, desc string, entries func() int) *Counter {
	mu.Lock()
	defer mu.Unlock()
	if c, ok := counters[name]; ok {
		return c
	}
	c := &Counter{name: name, desc: desc, entries: entries}
	counters[name] = c
	return c
}

// Snapshot returns the counts of every registered cache, sorted by name.
func Snapshot() []Stat {
	mu.Lock()
	list := make([]*Counter, 0, len(counters))
	for _, c := range counters {
		list = append(list, c)
	}
	mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	out := make([]Stat, 0, len(list))
	for _, c := range list {
		s := Stat{Name: c.name, Description: c.desc, Hits: c.hits.Load(), Misses: c.misses.Load()}
		if n := s.Hits + s.Misses; n > 0 {
			r := float64(s.Hits) / float64(n)
			s.Ratio = &r
		}
		if c.entries != nil {
			e := c.entries()
			s.Entries = &e
		}
		out = append(out, s)
	}
	return out
}
