package ratelimit

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Policy defines the rate and burst budget for a specific tool.
type Policy struct {
	Limit rate.Limit // tokens replenished per second
	Burst int        // maximum tokens held in the bucket
}

type MemoryLimiter struct {
	mu            sync.RWMutex
	buckets       map[string]*rate.Limiter
	policies      map[string]Policy
	defaultPolicy Policy
}

// NewMemoryLimiter initializes an in-memory rate limiter with per-tool policies.
func NewMemoryLimiter(policies map[string]Policy, defaultPolicy Policy) *MemoryLimiter {
	return &MemoryLimiter{
		buckets:       make(map[string]*rate.Limiter),
		policies:      policies,
		defaultPolicy: defaultPolicy,
	}
}

// Allow reports whether an action by agentID on tool may happen right now.
func (m *MemoryLimiter) Allow(agentID, tool string) bool {
	limiter := m.getLimiter(agentID, tool)
	return limiter.Allow()
}

// getLimiter retrieves or creates a token bucket for a specific (agentID, tool) key.
func (m *MemoryLimiter) getLimiter(agentID, tool string) *rate.Limiter {
	key := fmt.Sprintf("%s:%s", agentID, tool)

	// Read lock: fast path for existing buckets
	m.mu.RLock()
	limiter, exists := m.buckets[key]
	m.mu.RUnlock()

	if exists {
		return limiter
	}

	// Write lock: slow path to create new bucket
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check lock in case another goroutine created it
	if limiter, exists = m.buckets[key]; exists {
		return limiter
	}

	// Lookup policy for this tool, fallback to default
	pol, ok := m.policies[tool]
	if !ok {
		pol = m.defaultPolicy
	}

	limiter = rate.NewLimiter(pol.Limit, pol.Burst)
	m.buckets[key] = limiter
	return limiter
}

// Helper to convert human-friendly (count, window) into rate.Limit
// e.g. Per(10, time.Minute) -> 10 tokens per 60 seconds
func Per(count int, d time.Duration) rate.Limit {
	return rate.Every(d / time.Duration(count))
}
