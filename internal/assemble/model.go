package assemble

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Transaction is one complete HTTP request/response exchange between two services.
type Transaction struct {
	ID            string            `json:"id"`
	Time          time.Time         `json:"ts"`
	DurationMs    float64           `json:"duration_ms"`
	ClientService string            `json:"client_service"`
	ServerService string            `json:"server_service"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	ReqHeaders    map[string]string `json:"req_headers"`
	ReqBody       string            `json:"req_body"`
	Status        int               `json:"status"`
	RespHeaders   map[string]string `json:"resp_headers"`
	RespBody      string            `json:"resp_body"`
	Src           string            `json:"src"`     // client ip:port
	Dst           string            `json:"dst"`     // server ip:port
	Sides         []string          `json:"seen_by"` // which capture points saw it: client, server
	Node          string            `json:"node,omitempty"`

	startNs uint64
}

// Store keeps recent transactions and fans out updates to subscribers.
type Store struct {
	mu      sync.RWMutex
	items   []*Transaction // oldest first
	byID    map[string]*Transaction
	max     int
	subs    map[chan Transaction]struct{}
	persist *os.File
	total   int64 // transactions ever created (items is capped)
}

func NewStore(max int) *Store {
	return &Store{max: max, byID: map[string]*Transaction{}, subs: map[chan Transaction]struct{}{}}
}

// Publish stores (or replaces, by pointer identity) a transaction and notifies subscribers.
func (s *Store) Publish(t *Transaction, isNew bool) {
	s.mu.Lock()
	if isNew {
		s.total++
		s.items = append(s.items, t)
		if len(s.items) > s.max {
			s.items = s.items[len(s.items)-s.max:]
		}
	}
	s.byID[t.ID] = t
	if len(s.byID) > 2*s.max {
		s.byID = map[string]*Transaction{}
		for _, it := range s.items {
			s.byID[it.ID] = it
		}
	}
	if s.persist != nil {
		b, _ := json.Marshal(t)
		s.persist.Write(append(b, '\n'))
	}
	cp := *t
	subs := make([]chan Transaction, 0, len(s.subs))
	for c := range s.subs {
		subs = append(subs, c)
	}
	s.mu.Unlock()
	for _, c := range subs {
		select {
		case c <- cp:
		default: // slow consumer: drop
		}
	}
}

// Snapshot returns copies of all stored transactions, oldest first.
func (s *Store) Snapshot() []Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Transaction, len(s.items))
	for i, t := range s.items {
		out[i] = *t
	}
	return out
}

func (s *Store) Subscribe() (chan Transaction, func()) {
	c := make(chan Transaction, 256)
	s.mu.Lock()
	s.subs[c] = struct{}{}
	s.mu.Unlock()
	return c, func() { s.mu.Lock(); delete(s.subs, c); s.mu.Unlock() }
}

// Mutate lets the assembler update a stored transaction under the lock.
func (s *Store) Mutate(fn func()) { s.mu.Lock(); fn(); s.mu.Unlock() }

// Upsert inserts or replaces a transaction by id (used by the collector's ingest endpoint).
func (s *Store) Upsert(t Transaction) {
	s.mu.RLock()
	old := s.byID[t.ID]
	s.mu.RUnlock()
	if old == nil {
		cp := t
		s.Publish(&cp, true)
		return
	}
	s.Mutate(func() { *old = t })
	s.Publish(old, false)
}

// Get returns a copy of the transaction with this id.
func (s *Store) Get(id string) (Transaction, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	if !ok {
		return Transaction{}, false
	}
	return *t, true
}

// EnablePersistence loads previous transactions from a JSONL file and appends new updates to it.
func (s *Store) EnablePersistence(path string) error {
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var t Transaction
			if json.Unmarshal(sc.Bytes(), &t) != nil {
				continue
			}
			if old := s.byID[t.ID]; old != nil {
				*old = t
			} else {
				cp := t
				s.items = append(s.items, &cp)
				s.byID[t.ID] = &cp
			}
		}
		f.Close()
		if len(s.items) > s.max {
			s.items = s.items[len(s.items)-s.max:]
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	s.persist = f
	return nil
}

// Clear drops all stored transactions and empties the persistence file.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = nil
	s.byID = map[string]*Transaction{}
	s.total = 0
	if s.persist != nil {
		s.persist.Truncate(0)
	}
}

// Len returns the number of stored transactions.
func (s *Store) Len() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.items) }

// Total returns how many transactions were ever created.
func (s *Store) Total() int64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.total }
