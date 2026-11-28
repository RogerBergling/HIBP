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
		if event.Category == "auth_failure" {
			// Authentication failures are critical regardless of which
			// collector or device produced the event.
			event.Severity = "critical"
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
		if len(event.Message) > 4096 {
			event.Message = event.Message[:4096]
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
	return s.listHostEvents(limit, "", "")
}

// ListHostEventsFiltered optionally restricts the list to one severity so a
// dashboard severity filter can reach events older than the newest page.
func (s *Store) ListHostEventsFiltered(limit int, since, severity string) ([]HostEvent, error) {
	return s.listHostEvents(limit, since, severity)
}

func (s *Store) listHostEvents(limit int, since, severity string) ([]HostEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id,host_id,event_id,source,category,severity,unit,username,
		remote_ip,message,occurred_at,received_at FROM host_events`
	where := make([]string, 0, 2)
	args := []any{}
	if since != "" {
		where = append(where, "occurred_at>=?")
		args = append(args, since)
	}
	if severity != "" {
		where = append(where, "severity=?")
		args = append(args, severity)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
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

// HostEventSummaryItem groups events by category or host.
type HostEventSummaryItem struct {
	Name     string `json:"name"`
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
	Warning  int    `json:"warning"`
}

// HostEventSummary powers the security dashboard. Counts cover the requested
// time window, not just the bounded event list.
type HostEventSummary struct {
	Total          int                    `json:"total"`
	Critical       int                    `json:"critical"`
	Warning        int                    `json:"warning"`
	Info           int                    `json:"info"`
	Other          int                    `json:"other"`
	LastOccurredAt string                 `json:"last_occurred_at"`
	LastCritical   string                 `json:"last_critical"`
	LastWarning    string                 `json:"last_warning"`
	LastInfo       string                 `json:"last_info"`
	Categories     []HostEventSummaryItem `json:"categories"`
	Hosts          []HostEventSummaryItem `json:"hosts"`
}

// SummarizeHostEvents aggregates events for the security dashboard. An empty
// since value covers every retained event.
func (s *Store) SummarizeHostEvents(since string) (HostEventSummary, error) {
	summary := HostEventSummary{
		Categories: make([]HostEventSummaryItem, 0),
		Hosts:      make([]HostEventSummaryItem, 0),
	}
	where := ""
	args := []any{}
	if since != "" {
		where = " WHERE occurred_at>=?"
		args = append(args, since)
	}
	rows, err := s.db.Query(`SELECT severity,COUNT(*),COALESCE(MAX(occurred_at),'')
		FROM host_events`+where+` GROUP BY severity`, args...)
	if err != nil {
		return summary, err
	}
	for rows.Next() {
		var severity, last string
		var count int
		if err := rows.Scan(&severity, &count, &last); err != nil {
			_ = rows.Close()
			return summary, err
		}
		summary.Total += count
		switch severity {
		case "critical":
			summary.Critical = count
			summary.LastCritical = last
		case "warning":
			summary.Warning = count
			summary.LastWarning = last
		case "info":
			summary.Info = count
			summary.LastInfo = last
		default:
			summary.Other += count
		}
	}
	if err := rows.Close(); err != nil {
		return summary, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(occurred_at),'') FROM host_events`+where,
		args...).Scan(&summary.LastOccurredAt); err != nil {
		return summary, err
	}
	categoryRows, err := s.db.Query(`SELECT category,COUNT(*),
		SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),
		SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END)
		FROM host_events`+where+` GROUP BY category
		ORDER BY SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) DESC,
		COUNT(*) DESC,category LIMIT 8`, args...)
	if err != nil {
		return summary, err
	}
	for categoryRows.Next() {
		var item HostEventSummaryItem
		if err := categoryRows.Scan(&item.Name, &item.Total, &item.Critical, &item.Warning); err != nil {
			_ = categoryRows.Close()
			return summary, err
		}
		summary.Categories = append(summary.Categories, item)
	}
	if err := categoryRows.Close(); err != nil {
		return summary, err
	}
	hostRows, err := s.db.Query(`SELECT host_id,COUNT(*),
		SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),
		SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END)
		FROM host_events`+where+` GROUP BY host_id
		ORDER BY SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) DESC,
		COUNT(*) DESC,host_id LIMIT 8`, args...)
	if err != nil {
		return summary, err
	}
	for hostRows.Next() {
		var item HostEventSummaryItem
		if err := hostRows.Scan(&item.Name, &item.Total, &item.Critical, &item.Warning); err != nil {
			_ = hostRows.Close()
			return summary, err
		}
		summary.Hosts = append(summary.Hosts, item)
	}
	return summary, hostRows.Close()
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
