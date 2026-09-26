package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
	"github.com/strazyuk/AuthGaurd/internal/judge"
)

func main() {
	apiKey := os.Getenv("JEV_AI_API_KEY")
	if apiKey == "" {
		log.Println("=======================================================================")
		log.Println("WARNING: JEV_AI_API_KEY environment variable is not set.")
		log.Println("To run live requests, set JEV_AI_API_KEY in your environment or .env file.")
		log.Println("Example: export JEV_AI_API_KEY=\"your_jev_ai_api_key\"")
		log.Println("=======================================================================")
		os.Exit(1)
	}

	fmt.Println("==========================================================")
	fmt.Println(" AgentGaurd Jev AI Judge Escalation Layer Demo")
	fmt.Println("==========================================================")

	// Create Judge instance with 5-minute cache TTL and 0.60 hazard threshold
	j := judge.New("", apiKey, 5*time.Minute, 0.60)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Connection Check (Zero token cost)
	fmt.Println("\n[Step 1] Checking API connection & available models (GET /v1/models)...")
	models, err := j.CheckConnection(ctx)
	if err != nil {
		log.Fatalf("Connection check failed: %v", err)
	}
	fmt.Printf("✓ Connection successful! Available models: %d\n", len(models))
	for _, m := range models {
		fmt.Printf("   - %s\n", m.ID)
	}

	// 2. Action Evaluation (Uses Jev AI account balance)
	fmt.Println("\n[Step 2] Evaluating ambiguous tool action via Jev System One...")
	sampleAction := firewall.Action{
		ID:        "action-demo-101",
		AgentID:   "agent-alpha",
		SessionID: "session-777",
		Tool:      "run_shell",
		Args:      map[string]any{"cmd": "curl -s https://api.github.com/repos"},
		Timestamp: time.Now(),
	}

	start := time.Now()
	decision1, err := j.Judge(ctx, sampleAction)
	elapsed1 := time.Since(start).Milliseconds()

	if err != nil {
		log.Fatalf("Decision evaluation call failed: %v", err)
	}

	fmt.Println("Verdict (1st execution - Network API Call):")
	fmt.Printf(" - Allowed:   %v\n", decision1.Allow)
	fmt.Printf(" - Source:    %s\n", decision1.Source)
	fmt.Printf(" - Reason:    %s\n", decision1.Reason)
	fmt.Printf(" - Latency:   %d ms\n", elapsed1)

	// 3. Fast-Path In-Memory Cache Hit (<1ms)
	fmt.Println("\n[Step 3] Evaluating identical tool action (Testing fast-path deduplication cache)...")
	start2 := time.Now()
	decision2, err := j.Judge(ctx, sampleAction)
	elapsed2 := time.Since(start2).Milliseconds()

	if err != nil {
		log.Fatalf("Cached decision call failed: %v", err)
	}

	fmt.Println("Verdict (2nd execution - Cache Hit):")
	fmt.Printf(" - Allowed:   %v\n", decision2.Allow)
	fmt.Printf(" - Source:    %s\n", decision2.Source)
	fmt.Printf(" - Reason:    %s\n", decision2.Reason)
	fmt.Printf(" - Latency:   %d ms (<1ms fast path)\n", elapsed2)

	fmt.Println("\n==========================================================")
	fmt.Println(" AgentGaurd Judge Layer Verification Complete!")
	fmt.Println("==========================================================")
}
