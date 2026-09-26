package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
)

const (
	DefaultEndpoint       = "https://jev-ai.pro/api/v1/systemone"
	DefaultModelsEndpoint = "https://jev-ai.pro/api/v1/models"
	DefaultModel          = "jev-latest"
	DefaultHazardThreshold = 0.60
	DefaultTTL            = 5 * time.Minute
)

type cachedVerdict struct {
	decision firewall.Decision
	expires  time.Time
}

// Judge orchestrates AgentGaurd Jev AI System One escalations.
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

// Option defines a functional configuration option for Judge.
type Option func(*Judge)

// WithEndpoint overrides the default decision endpoint.
func WithEndpoint(endpoint string) Option {
	return func(j *Judge) {
		j.endpoint = endpoint
	}
}

// WithModel overrides the default model (default: jev-latest).
func WithModel(model string) Option {
	return func(j *Judge) {
		j.model = model
	}
}

// WithThreshold sets the hazard threshold (0.0 to 1.0) above which actions are denied (default: 0.60).
func WithThreshold(threshold float64) Option {
	return func(j *Judge) {
		j.threshold = threshold
	}
}

// WithTTL sets the cache expiration duration for verdicts (default: 5m).
func WithTTL(ttl time.Duration) Option {
	return func(j *Judge) {
		j.ttl = ttl
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(j *Judge) {
		j.httpClient = client
	}
}

// New creates an instance of the AgentGaurd Jev System One Judge.
func New(endpoint, apiKey string, ttl time.Duration, hazardThreshold float64, opts ...Option) *Judge {
	if apiKey == "" {
		apiKey = os.Getenv("JEV_AI_API_KEY")
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if hazardThreshold <= 0 {
		hazardThreshold = DefaultHazardThreshold
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	j := &Judge{
		endpoint:  endpoint,
		apiKey:    apiKey,
		model:     DefaultModel,
		threshold: hazardThreshold,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		cache: make(map[string]cachedVerdict),
		ttl:   ttl,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

// NewJevJudge is a convenience constructor for Jev AI Judge.
func NewJevJudge(apiKey string, opts ...Option) (*Judge, error) {
	if apiKey == "" {
		apiKey = os.Getenv("JEV_AI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("JEV_AI_API_KEY is required and must be set in environment or passed explicitly")
	}
	return New(DefaultEndpoint, apiKey, DefaultTTL, DefaultHazardThreshold, opts...), nil
}

// Jev System One Request Contracts
type jevQuestion struct {
	Type         string   `json:"type"` // "noul" | "choice" | "score"
	Instructions string   `json:"instructions"`
	Choices      []string `json:"choices,omitempty"`
}

type jevRequest struct {
	Model     string                 `json:"model"`
	State     any                    `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevAnswer struct {
	Noul       float64 `json:"noul,omitempty"`
	Choice     string  `json:"choice,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type jevResponse struct {
	Model     string               `json:"model,omitempty"`
	Answers   map[string]jevAnswer `json:"answers"`
	ElapsedMS int64                `json:"elapsedMs,omitempty"`
	Usage     struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage,omitempty"`
}

// ModelInfo represents a model returned by the /v1/models endpoint.
type ModelInfo struct {
	ID     string `json:"id"`
	Object string `json:"object,omitempty"`
}

type modelsResponse struct {
	Data []ModelInfo `json:"data"`
}

// CheckConnection checks API connectivity and authentication without model inference (Zero token usage).
func (j *Judge) CheckConnection(ctx context.Context) ([]ModelInfo, error) {
	if j.apiKey == "" {
		return nil, fmt.Errorf("JEV_AI_API_KEY is missing")
	}

	// Derive models endpoint from decision endpoint
	modelsURL := DefaultModelsEndpoint
	if strings.Contains(j.endpoint, "/v1/systemone") {
		modelsURL = strings.Replace(j.endpoint, "/v1/systemone", "/v1/models", 1)
	} else if j.endpoint != "" {
		modelsURL = strings.TrimSuffix(j.endpoint, "/") + "/v1/models"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+j.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection check request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connection check returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var res modelsResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, fmt.Errorf("failed to decode models response: %w", err)
	}

	return res.Data, nil
}

// Judge evaluates the security implications of an intercepted action.
// Implements the firewall.Judge interface.
func (j *Judge) Judge(ctx context.Context, act firewall.Action) (*firewall.Decision, error) {
	cacheKey := j.hashAction(act)

	// 1. In-memory Deduplication Check (Fast Path <1ms)
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
	httpReq.Header.Set("Accept", "application/json")

	// 4. Dispatch Request with Fail-Secure Fallback
	resp, err := j.httpClient.Do(httpReq)
	if err != nil {
		return failSecure(fmt.Sprintf("Jev request failed or timed out: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return failSecure(fmt.Sprintf("Jev returned non-200 status %d: %s", resp.StatusCode, string(respBody))), nil
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
	if threatCategory == "" {
		threatCategory = "unclassified"
	}

	// 5. Evaluate Probability Threshold
	isAllowed := hazardAns.Noul < j.threshold
	var reason string
	if isAllowed {
		reason = fmt.Sprintf("AgentGaurd Jev passed: hazard probability %.2f (category: %s)", hazardAns.Noul, threatCategory)
	} else {
		reason = fmt.Sprintf("Blocked by AgentGaurd Jev: high hazard probability %.2f (threat: %s, confidence: %.2f)",
			hazardAns.Noul, threatCategory, hazardAns.Confidence)
	}

	decision := firewall.Decision{
		Allow:     isAllowed,
		Reason:    reason,
		Source:    "llm_judge",
		Tool:      act.Tool,
		Args:      act.Args,
		Timestamp: time.Now(),
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
		Reason: fmt.Sprintf("%s (AgentGaurd fail-secure deny)", reason),
		Source: "llm_judge",
	}
}

func (j *Judge) hashAction(act firewall.Action) string {
	argsBytes, _ := json.Marshal(act.Args)
	raw := fmt.Sprintf("%s:%s:%s", act.AgentID, act.Tool, string(argsBytes))
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}
