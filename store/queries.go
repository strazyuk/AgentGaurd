package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type AuditEntry struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	SessionID string         `json:"session_id"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Allowed   bool           `json:"allowed"`
	Reason    string         `json:"reason"`
	Source    string         `json:"source"`
	RuleID    string         `json:"rule_id,omitempty"`
	LatencyMS int64          `json:"latency_ms"`
	CreatedAt time.Time      `json:"created_at"`
}

type Stats struct {
	TotalRequests int64            `json:"total_requests"`
	TotalBlocked  int64            `json:"total_blocked"`
	TotalAllowed  int64            `json:"total_allowed"`
	AvgLatencyMS  float64          `json:"avg_latency_ms"`
	TopRules      map[string]int64 `json:"top_rules"`
}

// GetRecent returns the latest N records ordered by created_at desc.
func (s *Store) GetRecent(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
	SELECT id, agent_id, session_id, tool, args_json, allowed, reason, source, COALESCE(rule_id, ''), latency_ms, created_at
	FROM audit_logs
	ORDER BY created_at DESC
	LIMIT ?
	`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var argsRaw string
		var allowedInt int

		err := rows.Scan(
			&e.ID, &e.AgentID, &e.SessionID, &e.Tool, &argsRaw,
			&allowedInt, &e.Reason, &e.Source, &e.RuleID,
			&e.LatencyMS, &e.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		e.Allowed = allowedInt == 1
		_ = json.Unmarshal([]byte(argsRaw), &e.Args)
		entries = append(entries, e)
	}

	return entries, nil
}

// GetStats returns aggregate performance and block metrics.
func (s *Store) GetStats(ctx context.Context) (Stats, error) {
	var st Stats
	st.TopRules = make(map[string]int64)

	query := `
	SELECT 
		COUNT(*),
		COALESCE(SUM(CASE WHEN allowed = 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN allowed = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(AVG(latency_ms), 0.0)
	FROM audit_logs
	`

	row := s.db.QueryRowContext(ctx, query)
	if err := row.Scan(&st.TotalRequests, &st.TotalBlocked, &st.TotalAllowed, &st.AvgLatencyMS); err != nil {
		if err == sql.ErrNoRows {
			return st, nil
		}
		return st, err
	}

	ruleQuery := `
	SELECT rule_id, COUNT(*) 
	FROM audit_logs 
	WHERE rule_id != '' 
	GROUP BY rule_id 
	ORDER BY COUNT(*) DESC 
	LIMIT 5
	`
	rows, err := s.db.QueryContext(ctx, ruleQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rID string
			var count int64
			if err := rows.Scan(&rID, &count); err == nil {
				st.TopRules[rID] = count
			}
		}
	}

	return st, nil
}