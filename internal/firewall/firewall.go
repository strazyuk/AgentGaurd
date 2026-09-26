package firewall

import (
	"context"
	"fmt"
	"time"
)

type firewall struct {
	evaluator Evaluator
	limiter   Limiter
	judge     Judge
}

// New creates a firewall with the given pipeline components.
// Any component may be nil to skip that stage.
func New(evaluator Evaluator, limiter Limiter, judge Judge) *firewall {
	return &firewall{
		evaluator: evaluator,
		limiter:   limiter,
		judge:     judge,
	}
}

// Check runs an Action through the full firewall pipeline:
// 1. Static rule evaluator  2. Rate limiter  3. LLM/human judge  4. Default policy
func (f *firewall) Check(ctx context.Context, act Action) (Decision, error) {
	start := time.Now()

	// 1. Static rule evaluation
	if f.evaluator != nil {
		dec, err := f.evaluator.Evaluate(act)
		if err != nil {
			return Decision{}, fmt.Errorf("evaluator failed: %w", err)
		}
		if dec != nil {
			dec.LatencyMS = time.Since(start).Milliseconds()
			return *dec, nil
		}
	}

	// 2. Rate limiting
	if f.limiter != nil && !f.limiter.Allow(act.AgentID, act.Tool) {
		return Decision{
			Allow:     false,
			Reason:    fmt.Sprintf("rate limit exceeded for tool %s", act.Tool),
			Source:    "rate_limit",
			LatencyMS: time.Since(start).Milliseconds(),
		}, nil
	}

	// 3. Judge (LLM or human escalation)
	if f.judge != nil {
		dec, err := f.judge.Judge(ctx, act)
		if err == nil && dec != nil {
			dec.LatencyMS = time.Since(start).Milliseconds()
			return *dec, nil
		}
		// Fail-secure: if judge errors or context times out, fall through to default
	}

	// 4. Default policy
	return Decision{
		Allow:     true,
		Reason:    "passed default security policy",
		Source:    "default",
		LatencyMS: time.Since(start).Milliseconds(),
	}, nil
}
