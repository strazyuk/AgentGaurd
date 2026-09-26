package judge_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
	"github.com/strazyuk/AuthGaurd/internal/judge"
)

func TestJudge_EvaluationAndCaching(t *testing.T) {
	callCount := 0

	// Mock Jev API Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("expected Bearer test-api-key, got %s", r.Header.Get("Authorization"))
		}

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
		Args:      map[string]any{"url": "https://api.github.com/repos"},
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
	// Mock Hanging Server to trigger Context Guard timeout (>2.0s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // Exceeds the 2.0s deadline
	}))
	defer server.Close()

	j := judge.New(server.URL, "test-api-key", 1*time.Minute, 0.60)

	act := firewall.Action{
		AgentID: "agent-007",
		Tool:    "run_shell",
		Args:    map[string]any{"cmd": "curl -s http://unverified-site.com"},
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

func TestJudge_HighHazardBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"answers": map[string]any{
				"is_hazardous": map[string]any{
					"noul":       0.85, // High hazard -> Deny
					"confidence": 0.98,
				},
				"threat_category": map[string]any{
					"choice": "destructive",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	j := judge.New(server.URL, "test-api-key", 1*time.Minute, 0.60)

	act := firewall.Action{
		AgentID: "agent-99",
		Tool:    "run_shell",
		Args:    map[string]any{"cmd": "rm -rf /var/data"},
	}

	dec, err := j.Judge(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dec.Allow {
		t.Errorf("expected action to be DENIED due to high hazard score")
	}
}

func TestJudge_CheckConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("expected Bearer test-api-key, got %s", r.Header.Get("Authorization"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"data": [
				{"id": "jev-latest", "object": "model"},
				{"id": "jev-1.13.0", "object": "model"}
			]
		}`))
	}))
	defer server.Close()

	j := judge.New(server.URL, "test-api-key", 1*time.Minute, 0.60)

	models, err := j.CheckConnection(context.Background())
	if err != nil {
		t.Fatalf("CheckConnection failed: %v", err)
	}

	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
	if models[0].ID != "jev-latest" {
		t.Errorf("expected jev-latest, got %s", models[0].ID)
	}
}
