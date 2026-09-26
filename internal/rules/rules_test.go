package rules_test

import (
	"os"
	"testing"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
	"github.com/strazyuk/AuthGaurd/internal/rules"
)

func TestEngine_Evaluate(t *testing.T) {
	yamlData := `
rules:
  - id: block-destructive-shell
    tool: run_shell
    field: cmd
    type: regex
    pattern: "(?i)(rm\\s+-rf|drop\\s+table)"
    action: deny
    reason: "Destructive shell command"

  - id: cap-payment
    tool: make_payment
    field: amount
    type: max_threshold
    threshold: 500
    action: deny
    reason: "Payment exceeds threshold"
`
	tmpFile, err := os.CreateTemp("", "rules-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlData)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	engine, err := rules.LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	tests := []struct {
		name       string
		action     firewall.Action
		wantHit    bool
		wantAllow  bool
		wantRuleID string
	}{
		{
			name: "Blocked shell command",
			action: firewall.Action{
				Tool:      "run_shell",
				Args:      map[string]any{"cmd": "rm -rf /usr/lib"},
				Timestamp: time.Now(),
			},
			wantHit:    true,
			wantAllow:  false,
			wantRuleID: "block-destructive-shell",
		},
		{
			name: "Safe shell command passes through",
			action: firewall.Action{
				Tool:      "run_shell",
				Args:      map[string]any{"cmd": "ls -lah"},
				Timestamp: time.Now(),
			},
			wantHit: false,
		},
		{
			name: "Blocked excessive payment",
			action: firewall.Action{
				Tool:      "make_payment",
				Args:      map[string]any{"amount": 750.0},
				Timestamp: time.Now(),
			},
			wantHit:    true,
			wantAllow:  false,
			wantRuleID: "cap-payment",
		},
		{
			name: "Safe payment passes through",
			action: firewall.Action{
				Tool:      "make_payment",
				Args:      map[string]any{"amount": 120.0},
				Timestamp: time.Now(),
			},
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := engine.Evaluate(tc.action)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tc.wantHit {
				if dec != nil {
					t.Fatalf("expected no rule hit, got %+v", dec)
				}
				return
			}

			if dec == nil {
				t.Fatalf("expected rule hit, got nil")
			}
			if dec.Allow != tc.wantAllow {
				t.Errorf("got allow=%v, want %v", dec.Allow, tc.wantAllow)
			}
			if dec.RuleID != tc.wantRuleID {
				t.Errorf("got ruleID=%q, want %q", dec.RuleID, tc.wantRuleID)
			}
		})
	}
}
