package bypassfast

import (
	"container/list"
	"sync"
	"time"
)

// scriptMissMemory is how long a script digest stays "known missing" after
// the API answered script_cache_miss for it. Within that window the client
// sends the script body straight away instead of paying the hash-first round
// trip again: a client that starts several solves for a brand-new script at
// once would otherwise have every one of them miss. A successful
// script-bearing call registers the script fleet-wide and forgets the miss.
const scriptMissMemory = 60 * time.Second

// scriptMemory is a small insertion-ordered record of recent script_cache_miss
// answers. It remembers only digests and timestamps, never challenge bodies,
// tokens, cookies or device data.
type scriptMemory struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	now      func() time.Time
	order    *list.List
	values   map[string]*list.Element
}

type scriptRecord struct {
	key      string
	missedAt time.Time
}

func newScriptMemory(capacity int) *scriptMemory {
	return &scriptMemory{
		capacity: capacity,
		ttl:      scriptMissMemory,
		now:      time.Now,
		order:    list.New(),
		values:   make(map[string]*list.Element, capacity),
	}
}

// recentlyMissed reports whether the API answered script_cache_miss for key
// within the memory window.
func (m *scriptMemory) recentlyMissed(key string) bool {
	if key == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	element, ok := m.values[key]
	if !ok {
		return false
	}
	if m.now().Sub(element.Value.(scriptRecord).missedAt) >= m.ttl {
		m.order.Remove(element)
		delete(m.values, key)
		return false
	}
	return true
}

// markMissed records that the API has no script for key.
func (m *scriptMemory) markMissed(key string) {
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record := scriptRecord{key: key, missedAt: m.now()}
	if element, exists := m.values[key]; exists {
		element.Value = record
		m.order.MoveToBack(element)
		return
	}
	if m.order.Len() == m.capacity {
		oldest := m.order.Front()
		delete(m.values, oldest.Value.(scriptRecord).key)
		m.order.Remove(oldest)
	}
	m.values[key] = m.order.PushBack(record)
}

// markRegistered forgets a miss: a script-bearing call for key succeeded, so
// the API now holds the script and hash-first calls will hit.
func (m *scriptMemory) markRegistered(key string) {
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if element, exists := m.values[key]; exists {
		m.order.Remove(element)
		delete(m.values, key)
	}
}

// len reports how many misses are remembered, expired entries included.
func (m *scriptMemory) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.order.Len()
}
