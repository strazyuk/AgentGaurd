Here is the complete, production-ready `JudgeLayerPlan.md` file. You can copy and save this directly into your repository documentation (`docs/JudgeLayerPlan.md` or root `JudgeLayerPlan.md`).

---

```markdown
# Sentinel Judge Layer: Architecture & Implementation Plan

This document outlines the design, API contracts, failure guarantees, and step-by-step implementation for Sentinel's **Judge Escalation Layer** (`internal/judge`), powered by **Jev AI (TypeSafe System One)**.

---

## 1. Architectural Role & Objective

Sentinel enforces security via a 4-stage pipeline:
1. **Static Rules Engine** (`internal/rules`) — Regex patterns, parameter bounds ($<0.1\text{ms}$).
2. **Rate Limiting** (`internal/ratelimit`) — Token bucket per agent/tool ($<0.1\text{ms}$).
3. **Judge Escalation** (`internal/judge`) — **Contextual classification and threat assessment**.
4. **Default Policy** — Baseline system guardrail.

### Why Jev AI System One?
Standard LLMs (OpenAI, Claude) generate tokens sequentially, leading to high latency ($1.5\text{s}–4.0\text{s}$), JSON parsing failures, and conversational hallucinations.

Jev is a **System One non-autoregressive decision model**:
- **70ms–500ms response time**: Operates directly in the real-time execution loop without blocking the agent.
- **Strictly Typed Primitives**: Returns calibrated probabilities (`Noul`), ordinal risk ratings (`Score`), or categorizations (`Choice`) rather than free-form text.
- **Zero Hallucination / Zero Parsing Failures**: Schema conformance is guaranteed by construction.

---

## 2. Component Architecture & Data Flow

```text
                           Action In
                               │
                               ▼
                    ┌─────────────────────┐
                    │  hashAction(Action) │
                    └──────────┬──────────┘
                               │ SHA-256 Signature
                               ▼
                     /───────────────────\
                    <   In-Memory Cache   >
                    <   TTL Hit Valid?    >
                     \───────────────────/
                        │               │
                 [YES]  │               │ [NO]
         ┌──────────────┘               └─────────────┐
         ▼                                            ▼
  Return Cached                               ┌───────────────┐
  Decision (<1ms)                             │ Context Guard │ (Hard 2.0s Deadline)
                                              └───────┬───────┘
                                                      │
                                                      ▼
                                            ┌───────────────────┐
                                            │ State & Question  │
                                            │ Payload Builder   │
                                            └─────────┬─────────┘
                                                      │ HTTP POST
                                                      ▼
                                            ┌───────────────────┐
                                            │  Jev System One   │
                                            │ (api.typesafe.ai) │
                                            └─────────┬─────────┘
                                                      │
                                   ┌──────────────────┴──────────────────┐
                                   │                                     │
                             [200 OK Response]                     [Timeout / 5xx]
                                   │                                     │
                                   ▼                                     ▼
                        ┌─────────────────────┐               ┌─────────────────────┐
                        │ Calibrated Noul/Conf│               │ Fail-Secure Deny    │
                        │ Threshold Evaluator │               │ (Allow: false)      │
                        └──────────┬──────────┘               └──────────┬──────────┘
                                   │                                     │
                                   ├──────────────┬──────────────────────┘
                                   ▼              │
                             Update Cache         ▼
                             (Write Lock)   Return Decision

```

---

## 3. Threat Model & Question Design

When evaluating ambiguous actions, Sentinel poses two structured questions to Jev over the intercepted action state:

1. **`is_hazardous` (`Noul` - Binary Probability $[0.0, 1.0]$):**
* Assesses indicators of remote command execution, data exfiltration, secret theft, or lateral movement.


2. **`threat_category` (`Choice` - Categorical Classification):**
* Maps the intent to an audit bucket: `benign`, `credential_access`, `exfiltration`, `destructive`, or `unauthorized_network`.



### Threshold Logic

* **Allow Verdict:** `answers.is_hazardous.noul < 0.60`
* **Block Verdict:** `answers.is_hazardous.noul >= 0.60`
* **Fail-Secure Rule:** On network errors, non-200 responses, or timeouts exceeding 2 seconds, Sentinel immediately emits `Allow: false` with source `llm_judge`.

---

## 4. Implementation Code

### 4.1 Data Types & Client (`internal/judge/judge.go`)

```go
package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"[github.com/turbok12/AgentGaurd/internal/firewall](https://github.com/turbok12/AgentGaurd/internal/firewall)"
)

// CachedVerdict stores previous evaluation decisions.
type cachedVerdict struct {
	decision firewall.Decision
	expires  time.Time
}

// Judge orchestrates Jev System One escalations.
type Judge struct {
	endpoint   string
	apiKey     string
	model      string
	httpClient *http.Client
	threshold  float64

	mu    sync.RWMutex
	cache map[string]cachedVerdict
	ttl   time.Duration
}

// Jev System One Request Contracts
type jevRequest struct {
	Model     string                 `json:"model"`
	State     any                    `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevQuestion struct {
	Type         string   `json:"type"` // "noul" | "choice" | "score"
	Instructions string   `json:"instructions"`
	Choices      []string `json:"choices,omitempty"`
}

// Jev System One Response Contracts
type jevResponse struct {
	Answers map[string]struct {
		Noul       float64  `json:"noul,omitempty"`
		Choice     string   `json:"choice,omitempty"`
		Confidence float64  `json:"confidence"`
	} `json:"answers"`
	ElapsedMS int64 `json:"elapsedMs"`
}

// New creates an instance of the Jev System One Judge.
func New(endpoint, apiKey string, ttl time.Duration, hazardThreshold float64) *Judge {
	if endpoint == "" {
		endpoint = "[https://api.typesafe.ai/v1/systemone](https://api.typesafe.ai/v1/systemone)"
	}
	if hazardThreshold <= 0 {
		hazardThreshold = 0.60
	}
	return &Judge{
		endpoint:   endpoint,
		apiKey:     apiKey,
		model:      "jev-latest",
		threshold:  hazardThreshold,
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cache:      make(map[string]cachedVerdict),
		ttl:        ttl,
	}
}

// Judge evaluates the security implications of an intercepted action.
func (j *Judge) Judge(ctx context.Context, act firewall.Action) (*firewall.Decision, error) {
	cacheKey := j.hashAction(act)

	// 1. In-memory Deduplication Check (Fast Path)
	j.mu.RLock()
	cached, found := j.cache[cacheKey]
	j.mu.RUnlock()

	if found && time.Now().Before(cached.expires) {
		dec := cached.decision
		dec.Reason = fmt.Sprintf("[cached] %s", dec.Reason)
		return &dec, nil
	}

	// 2. Prepare Context Guard (2-Second Execution Ceiling)
	evalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// 3. Assemble Jev System One Payload
	reqPayload := jevRequest{
		Model: j.model,
		State: map[string]any{
			"agent_id":   act.AgentID,
			"session_id": act.SessionID,
			"tool":       act.Tool,
			"args":       act.Args,
			"timestamp":  act.Timestamp,
		},
		Questions: map[string]jevQuestion{
			"is_hazardous": {
				Type:         "noul",
				Instructions: "Does this action involve data exfiltration, privilege escalation, unauthorized network communication, or sensitive file tampering?",
			},
			"threat_category": {
				Type:         "choice",
				Instructions: "Identify the primary threat vector of this action.",
				Choices:      []string{"benign", "credential_access", "exfiltration", "destructive", "unauthorized_network"},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return failSecure("failed to marshal Jev payload"), nil
	}

	httpReq, err := http.NewRequestWithContext(evalCtx, http.MethodPost, j.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return failSecure("failed to construct HTTP request"), nil
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+j.apiKey)

	// 4. Dispatch Request with Fail-Secure Fallback
	resp, err := j.httpClient.Do(httpReq)
	if err != nil {
		return failSecure(fmt.Sprintf("Jev request failed or timed out: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return failSecure(fmt.Sprintf("Jev returned non-200 status: %d", resp.StatusCode)), nil
	}

	var jevRes jevResponse
	if err := json.NewDecoder(resp.Body).Decode(&jevRes); err != nil {
		return failSecure("failed to decode Jev response"), nil
	}

	hazardAns, ok := jevRes.Answers["is_hazardous"]
	if !ok {
		return failSecure("malformed response: missing 'is_hazardous' evaluation"), nil
	}

	threatCategory := jevRes.Answers["threat_category"].Choice

	// 5. Evaluate Probability Threshold
	isAllowed := hazardAns.Noul < j.threshold
	var reason string
	if isAllowed {
		reason = fmt.Sprintf("Jev passed: hazard probability %.2f (category: %s)", hazardAns.Noul, threatCategory)
	} else {
		reason = fmt.Sprintf("Blocked by Jev: high hazard probability %.2f (threat: %s, confidence: %.2f)",
			hazardAns.Noul, threatCategory, hazardAns.Confidence)
	}

	decision := firewall.Decision{
		Allow:  isAllowed,
		Reason: reason,
		Source: "llm_judge",
	}

	// 6. Cache Verdict Under Write Lock
	j.mu.Lock()
	j.cache[cacheKey] = cachedVerdict{
		decision: decision,
		expires:  time.Now().Add(j.ttl),
	}
	j.mu.Unlock()

	return &decision, nil
}

func failSecure(reason string) *firewall.Decision {
	return &firewall.Decision{
		Allow:  false,
		Reason: fmt.Sprintf("%s (fail-secure deny)", reason),
		Source: "llm_judge",
	}
}

func (j *Judge) hashAction(act firewall.Action) string {
	argsBytes, _ := json.Marshal(act.Args)
	raw := fmt.Sprintf("%s:%s:%s", act.AgentID, act.Tool, string(argsBytes))
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

```

---

### 4.2 Unit & Integration Tests (`internal/judge/judge_test.go`)

This test suite covers both deterministic caching and dynamic mocking of the Jev System One API.

```go
package judge_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"[github.com/turbok12/AgentGaurd/internal/firewall](https://github.com/turbok12/AgentGaurd/internal/firewall)"
	"[github.com/turbok12/AgentGaurd/internal/judge](https://github.com/turbok12/AgentGaurd/internal/judge)"
)

func TestJudge_EvaluationAndCaching(t *testing.T) {
	callCount := 0

	// Mock Jev API Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"answers": map[string]any{
				"is_hazardous": map[string]any{
					"noul":       0.12, // Low hazard -> Allow
					"confidence": 0.95,
				},
				"threat_category": map[string]any{
					"choice": "benign",
				},
			},
			"elapsedMs": 85,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	j := judge.New(server.URL, "test-api-key", 2*time.Second, 0.60)

	act := firewall.Action{
		AgentID:   "agent-007",
		Tool:      "http_request",
		Args:      map[string]any{"url": "[https://api.github.com/repos](https://api.github.com/repos)"},
		Timestamp: time.Now(),
	}

	// First execution: should invoke Mock Server
	dec, err := j.Judge(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected action to be allowed, got denied")
	}
	if callCount != 1 {
		t.Errorf("expected 1 API call, got %d", callCount)
	}

	// Second execution: must hit cache (<1ms, no network call)
	decCached, err := j.Judge(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decCached.Allow {
		t.Fatalf("expected cached action to be allowed")
	}
	if callCount != 1 {
		t.Errorf("expected callCount to remain 1 due to cache, got %d", callCount)
	}
}

func TestJudge_FailSecureOnTimeout(t *testing.T) {
	// Mock Hanging Server to trigger Context Guard timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // Exceeds the 2.0s deadline
	}))
	defer server.Close()

	j := judge.New(server.URL, "test-api-key", 1*time.Minute, 0.60)

	act := firewall.Action{
		AgentID: "agent-007",
		Tool:    "run_shell",
		Args:    map[string]any{"cmd": "curl -s [http://unverified-site.com](http://unverified-site.com)"},
	}

	dec, err := j.Judge(context.Background(), act)
	if err != nil {
		t.Fatalf("pipeline returned error instead of fail-secure verdict: %v", err)
	}

	if dec.Allow {
		t.Fatalf("expected action to be DENIED on timeout (fail-secure)")
	}
	if dec.Source != "llm_judge" {
		t.Errorf("expected source 'llm_judge', got '%s'", dec.Source)
	}
}

```

---

## 5. Verification Checklist

1. **Unit Tests:** Execute `go test -v ./internal/judge/...` inside Docker to confirm caching and timeout mocks pass.
2. **Deterministic Fallbacks:** Confirm that simulating broken network connections results in `Allow: false` without crashing the daemon.
3. **Environment Setup:** Set `JEV_API_KEY` in `configs/` or container environment variables before running in live agent mode.

```

---

### Key Highlights Included in This Plan

1. **Jev Native Schema:** Implements the official `State` and `Questions` schema, requesting both a `Noul` (probability) and a `Choice` (threat classification) in a single parallel query.
2. **Context Guard:** Enforces a rigid 2.0-second deadline via Go's `context.WithTimeout`, cleanly handling hung connections and socket teardowns.
3. **Fail-Secure Default:** Guaranteed rejection (`Allow: false`) whenever upstream errors or deadlines trip.
4. **Mocked Test Suite:** Includes unit tests using `net/http/httptest` so you can verify cache deduplication and timeout protection locally without burning real API credits.

```