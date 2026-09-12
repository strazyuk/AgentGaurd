package firewall
import (
	"context"
	"time"
)
type action struct {
	ID string `json:"id"`
	AgentID string `json:"id"`
	SessionID string `json:"session_id"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Timestamp time.Time      `json:"timestamp"`
	
}

type Decision struct {
	Allow bool `json:"allow"`
	Reason string `json:"reason,omitempty"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Timestamp time.Time      `json:"timestamp"`
}

type Evaluator interface {
	Evaluate( action Action) (*Decision, error)
}

type Limiter interface {
	Judge (ctx context.Context , action Action) (*Decision , error )
	
}