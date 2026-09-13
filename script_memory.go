package bypassfast

import (
	"container/list"
	"sync"
)

// scriptMemory is a small insertion-ordered cache. It remembers only hashes
// and aliases, never challenge bodies, tokens, cookies, or device data.
type scriptMemory struct {
	mu       sync.Mutex
	capacity int
	order    *list.List
	values   map[string]*list.Element
}

type scriptRecord struct {
	key   string
	value string
}

func newScriptMemory(capacity int) *scriptMemory {
	return &scriptMemory{
		capacity: capacity,
		order:    list.New(),
		values:   make(map[string]*list.Element, capacity),
	}
}

func (m *scriptMemory) matches(key, value string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	element, ok := m.values[key]
	if !ok || value == "" || element.Value.(scriptRecord).value != value {
		return false
	}
	m.order.MoveToBack(element)
	return true
}

func (m *scriptMemory) put(key, value string) {
	if key == "" || value == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if element, exists := m.values[key]; exists {
		element.Value = scriptRecord{key: key, value: value}
		m.order.MoveToBack(element)
		return
	}
	if m.order.Len() == m.capacity {
		oldest := m.order.Front()
		delete(m.values, oldest.Value.(scriptRecord).key)
		m.order.Remove(oldest)
	}
	element := m.order.PushBack(scriptRecord{key: key, value: value})
	m.values[key] = element
}
