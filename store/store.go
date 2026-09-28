package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/strazyuk/AuthGaurd/internal/firewall"
	_ "modernc.org/sqlite"
)

type AuditRecord struct {
	Action   firewall.Action
	Decision firewall.Decision
}

type Store struct {
	db       *sql.DB
	queue    chan AuditRecord
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	dbPath   string
}

func New(dbPath string, queueBuffer int) (*Store, error) {
	// Enable WAL mode (Write-Ahead Logging) and foreign keys for high-performance concurrent reads
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Restrict to single writer to prevent write contention in SQLite
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithCancel(context.Background())

	s := &Store{
		db:      db,
		queue:   make(chan AuditRecord, queueBuffer),
		ctx:     ctx,
		cancel:  cancel,
		dbPath:  dbPath,
	}

	if err := s.migrate(); err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Start background single-writer consumer
	s.wg.Add(1)
	go s.worker()

	return s, nil
}

// Log pushes an audit event into the non-blocking channel.
// If the buffer is full, it drops or logs an alert rather than freezing the firewall.
func (s *Store) Log(act firewall.Action, dec firewall.Decision) {
	select {
	case s.queue <- AuditRecord{Action: act, Decision: dec}:
	default:
		slog.Warn("Audit queue full, dropping record to preserve pipeline throughput", "action_id", act.ID)
	}
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		session_id TEXT NOT NULL,
		tool TEXT NOT NULL,
		args_json TEXT NOT NULL,
		allowed INTEGER NOT NULL,
		reason TEXT NOT NULL,
		source TEXT NOT NULL,
		rule_id TEXT,
		latency_ms INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_agent_id ON audit_logs(agent_id);
	CREATE INDEX IF NOT EXISTS idx_created_at ON audit_logs(created_at);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) worker() {
	defer s.wg.Done()

	for {
		select {
		case record := <-s.queue:
			if err := s.insert(record); err != nil {
				slog.Error("Failed to persist audit log", "error", err, "action_id", record.Action.ID)
			}
		case <-s.ctx.Done():
			// Drain remaining records on graceful shutdown
			for len(s.queue) > 0 {
				record := <-s.queue
				_ = s.insert(record)
			}
			return
		}
	}
}

func (s *Store) insert(r AuditRecord) error {
	argsJSON, err := json.Marshal(r.Action.Args)
	if err != nil {
		argsJSON = []byte("{}")
	}

	allowedInt := 0
	if r.Decision.Allow {
		allowedInt = 1
	}

	query := `
	INSERT INTO audit_logs (
		id, agent_id, session_id, tool, args_json, allowed, reason, source, rule_id, latency_ms, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	timestamp := r.Action.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	_, err = s.db.Exec(query,
		r.Action.ID,
		r.Action.AgentID,
		r.Action.SessionID,
		r.Action.Tool,
		string(argsJSON),
		allowedInt,
		r.Decision.Reason,
		r.Decision.Source,
		r.Decision.RuleID,
		r.Decision.LatencyMS,
		timestamp,
	)
	return err
}

// Close gracefully stops the worker and closes the database.
func (s *Store) Close() error {
	s.cancel()
	s.wg.Wait()
	return s.db.Close()
}