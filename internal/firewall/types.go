package firewall

import (
	"context"
	"time"
)

// Action represents a tool call made by an agent that must be evaluated.
type Action struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	SessionID string         `json:"session_id"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Timestamp time.Time      `json:"timestamp"`
}

// Decision is the result of evaluating an Action through the firewall pipeline.
type Decision struct {
	Allow     bool           `json:"allow"`
	Reason    string         `json:"reason,omitempty"`
	Source    string         `json:"source,omitempty"`
	RuleID    string         `json:"rule_id,omitempty"`
	Tool      string         `json:"tool,omitempty"`
	Args      map[string]any `json:"args,omitempty"`
	Timestamp time.Time      `json:"timestamp,omitempty"`
	LatencyMS int64          `json:"latency_ms,omitempty"`
}

// Evaluator checks an Action against static rules and returns a Decision if matched.
// Returns nil Decision (no error) to signal no rule matched — pipeline continues.
type Evaluator interface {
	Evaluate(action Action) (*Decision, error)
}

// Limiter enforces rate limits per agent/tool. Returns true if the action is allowed.
type Limiter interface {
	Allow(agentID, tool string) bool
}

// Judge escalates ambiguous actions (e.g. to an LLM or human reviewer).
type Judge interface {
	Judge(ctx context.Context, action Action) (*Decision, error)
}