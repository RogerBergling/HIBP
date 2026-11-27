package store

import (
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
)

// HostEvent is one normalized monitoring/security event. Raw log lines are
// intentionally bounded and stored only in this redacted shape.
type HostEvent struct {
	ID         int64  `json:"id"`
	HostID     string `json:"host_id"`
	EventID    string `json:"event_id"`
	Source     string `json:"source"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Unit       string `json:"unit,omitempty"`
	Username   string `json:"username,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	Message    string `json:"message,omitempty"`
	OccurredAt string `json:"occurred_at"`
	ReceivedAt string `json:"received_at"`
}

func (s *Store) AddHostEvents(hostID string, events []HostEvent) error {
	if hostID == "" {
		return errors.New("host id is required")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	now := crypto.Now()
	for _, event := range events {
		event.EventID = strings.TrimSpace(event.EventID)
		if event.EventID == "" {
			continue
		}
		if event.Source == "" {
			event.Source = "unknown"
		}
		if event.Category == "" {
			event.Category = "log"
		}
		if event.Severity == "" {
			event.Severity = "info"
		}
		if event.OccurredAt == "" {
			event.OccurredAt = now
		}
		if event.Message == "" {
			event.Message = "event without message"
		}
		if len(event.Message) > 512 {
			event.Message = event.Message[:512]
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO host_events
			(host_id,event_id,source,category,severity,unit,username,remote_ip,message,occurred_at,received_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			hostID, event.EventID, event.Source, event.Category, event.Severity,
			event.Unit, event.Username, event.RemoteIP, event.Message, event.OccurredAt, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListHostEvents(limit int) ([]HostEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,host_id,event_id,source,category,severity,unit,username,
		remote_ip,message,occurred_at,received_at FROM host_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]HostEvent, 0, limit)
	for rows.Next() {
		var event HostEvent
		if err := rows.Scan(&event.ID, &event.HostID, &event.EventID, &event.Source, &event.Category,
			&event.Severity, &event.Unit, &event.Username, &event.RemoteIP, &event.Message,
			&event.OccurredAt, &event.ReceivedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) CountHostEventsSince(hostID, category, since string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM host_events
		WHERE host_id=? AND category=? AND occurred_at>=?`, hostID, category, since).Scan(&count)
	return count, err
}

// CountHostEventsMatching counts events from a source whose message contains
// the supplied text. An empty contains value matches every event from the
// source.
func (s *Store) CountHostEventsMatching(hostID, source, contains, since string) (int, error) {
	query := `SELECT COUNT(*) FROM host_events WHERE host_id=? AND occurred_at>=?`
	args := []any{hostID, since}
	if source != "" {
		query += " AND source LIKE ?"
		args = append(args, source+"%")
	}
	if contains != "" {
		query += " AND instr(lower(message), lower(?)) > 0"
		args = append(args, contains)
	}
	var count int
	err := s.db.QueryRow(query, args...).Scan(&count)
	return count, err
}

// ClearHostEvents deletes security/service event history. An empty hostID
// clears every host. The action is audited by the caller.
func (s *Store) ClearHostEvents(hostID string) (int64, error) {
	query := "DELETE FROM host_events"
	args := []any{}
	if strings.TrimSpace(hostID) != "" {
		query += " WHERE host_id=?"
		args = append(args, hostID)
	}
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	deleted, _ := result.RowsAffected()
	return deleted, nil
}

func (s *Store) DeleteHostEventsBefore(cutoff string) error {
	_, err := s.db.Exec("DELETE FROM host_events WHERE received_at < ?", cutoff)
	return err
}

func (s *Store) DeleteHostEventsBeforeForHost(hostID, cutoff string) error {
	_, err := s.db.Exec("DELETE FROM host_events WHERE host_id=? AND received_at < ?", hostID, cutoff)
	return err
}
