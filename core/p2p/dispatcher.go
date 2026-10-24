package p2p

import (
	"sync"
	"time"
)

var (
	relayDispatchBase = 3 * time.Second
	relayDispatchMax  = 15 * time.Second
)

type relayDispatchState struct {
	mu       sync.Mutex
	known    []string
	failures map[string]int
	until    map[string]time.Time
}

var relayDispatch = &relayDispatchState{
	failures: map[string]int{},
	until:    map[string]time.Time{},
}

func (s *relayDispatchState) remember(hostport string) {
	if hostport == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.known {
		if h == hostport {
			return
		}
	}
	s.known = append(s.known, hostport)
	if len(s.known) > 8 {
		s.known = s.known[1:]
	}
}

func (s *relayDispatchState) penalize(hostport string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.failures[hostport] + 1
	s.failures[hostport] = n
	d := relayDispatchBase << (n - 1)
	if d > relayDispatchMax || d <= 0 {
		d = relayDispatchMax
	}
	s.until[hostport] = time.Now().Add(d)
}

func (s *relayDispatchState) forgive(hostport string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, hostport)
	delete(s.until, hostport)
}

func (s *relayDispatchState) nextTo(current string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.known {
		if h == current {
			continue
		}
		if d, ok := s.until[h]; ok && time.Now().Before(d) {
			continue
		}
		return h
	}
	return ""
}

func (s *relayDispatchState) backoffLeft(hostport string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.until[hostport]; ok {
		return time.Until(d)
	}
	return 0
}
