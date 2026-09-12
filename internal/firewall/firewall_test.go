package firewall_test

import (
	"context"
	"testing"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
)

type mockEvaluator struct {
	decision *firewall.Decision
}

func (m *mockEvaluator) Evaluate(action firewall.Action) (*firewall.Decision, error) {
	return m.decision, nil
}

type mockLimiter struct {
	allow bool
}

func (m *mockLimiter) Allow(agentID, tool string) bool {
	return m.allow
}

func TestCheck_StaticRuleDeny(t *testing.T) {
	eval := &mockEvaluator{
		decision: &firewall.Decision{
			Allow:  false,
			Reason: "Blocked dangerous shell call",
			Source: "rule",
			RuleID: "block-rm",
		},
	}
	lim := &mockLimiter{allow: true}
	fw := firewall.New(eval, lim, nil)

	action := firewall.Action{
		ID:        "act-1",
		AgentID:   "demo-agent",
		Tool:      "run_shell",
		Args:      map[string]any{"cmd": "rm -rf /"},
		Timestamp: time.Now(),
	}

	dec, err := fw.Check(context.Background(), action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dec.Allow {
		t.Errorf("expected deny, got allow")
	}
	if dec.RuleID != "block-rm" {
		t.Errorf("expected rule ID block-rm, got %s", dec.RuleID)
	}
}

func TestCheck_RateLimitExceeded(t *testing.T) {
	eval := &mockEvaluator{decision: nil} // No rule match
	lim := &mockLimiter{allow: false}     // Limit hit
	fw := firewall.New(eval, lim, nil)

	action := firewall.Action{
		Tool: "send_email",
	}

	dec, err := fw.Check(context.Background(), action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dec.Allow {
		t.Errorf("expected rate limit block")
	}
	if dec.Source != "rate_limit" {
		t.Errorf("expected source rate_limit, got %s", dec.Source)
	}
}
