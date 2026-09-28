package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
	"github.com/strazyuk/AuthGaurd/store"
)

func TestStore_LogAndQuery(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_audit.db")

	s, err := store.New(dbPath, 100)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	act1 := firewall.Action{
		ID:        "act-101",
		AgentID:   "agent-alpha",
		SessionID: "sess-1",
		Tool:      "execute_code",
		Args:      map[string]any{"code": "print('hello')"},
		Timestamp: time.Now().Add(-10 * time.Second),
	}
	dec1 := firewall.Decision{
		Allow:     true,
		Reason:    "allowed by default",
		Source:    "rule",
		RuleID:    "rule-allow-code",
		LatencyMS: 15,
	}

	act2 := firewall.Action{
		ID:        "act-102",
		AgentID:   "agent-beta",
		SessionID: "sess-2",
		Tool:      "bash",
		Args:      map[string]any{"cmd": "rm -rf /"},
		Timestamp: time.Now(),
	}
	dec2 := firewall.Decision{
		Allow:     false,
		Reason:    "dangerous command detected",
		Source:    "rule",
		RuleID:    "rule-block-rm",
		LatencyMS: 25,
	}

	s.Log(act1, dec1)
	s.Log(act2, dec2)

	// Close store to flush worker queue and ensure persistence
	if err := s.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	// Reopen store to verify persistence
	s2, err := store.New(dbPath, 100)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer s2.Close()

	ctx := context.Background()

	// Verify GetRecent
	recent, err := s2.GetRecent(ctx, 10)
	if err != nil {
		t.Fatalf("failed to get recent audit entries: %v", err)
	}

	if len(recent) != 2 {
		t.Fatalf("expected 2 recent entries, got %d", len(recent))
	}

	// Entries should be ordered by created_at DESC
	if recent[0].ID != "act-102" || recent[1].ID != "act-101" {
		t.Errorf("unexpected entry ordering: first=%s, second=%s", recent[0].ID, recent[1].ID)
	}

	if !recent[1].Allowed {
		t.Errorf("expected act-101 to be allowed")
	}
	if recent[0].Allowed {
		t.Errorf("expected act-102 to be blocked")
	}

	if recent[0].RuleID != "rule-block-rm" {
		t.Errorf("expected rule_id rule-block-rm, got %s", recent[0].RuleID)
	}

	// Verify GetStats
	stats, err := s2.GetStats(ctx)
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}

	if stats.TotalRequests != 2 {
		t.Errorf("expected 2 total requests, got %d", stats.TotalRequests)
	}
	if stats.TotalAllowed != 1 {
		t.Errorf("expected 1 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.TotalBlocked)
	}
	if stats.AvgLatencyMS != 20.0 {
		t.Errorf("expected avg latency 20.0ms, got %f", stats.AvgLatencyMS)
	}

	if stats.TopRules["rule-block-rm"] != 1 || stats.TopRules["rule-allow-code"] != 1 {
		t.Errorf("unexpected top rules stats: %v", stats.TopRules)
	}
}

func TestStore_QueueOverflow(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "overflow_test.db")

	// Create store with buffer size of 1
	s, err := store.New(dbPath, 1)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	act := firewall.Action{
		ID:      "act-overflow",
		AgentID: "agent-test",
		Tool:    "test",
	}
	dec := firewall.Decision{Allow: true}

	// Rapidly log 10 records without blocking
	for i := 0; i < 10; i++ {
		s.Log(act, dec)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}
}

func TestStore_EmptyStats(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "empty_test.db")

	s, err := store.New(dbPath, 10)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	stats, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("failed to get stats on empty db: %v", err)
	}

	if stats.TotalRequests != 0 {
		t.Errorf("expected 0 requests, got %d", stats.TotalRequests)
	}

	recent, err := s.GetRecent(ctx, 50)
	if err != nil {
		t.Fatalf("failed to get recent on empty db: %v", err)
	}
	if len(recent) != 0 {
		t.Errorf("expected 0 recent entries, got %d", len(recent))
	}
}
