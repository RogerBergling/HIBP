package store

import (
	"github.com/RogerBergling/hibp/internal/crypto"
)

type IntegrationState struct {
	Source       string `json:"source"`
	EventKey     string `json:"event_key"`
	Status       string `json:"status"`
	Subject      string `json:"subject"`
	Detail       string `json:"detail"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	LastNotified string `json:"last_notified"`
}

type IntegrationEvent struct {
	ID        int64  `json:"id"`
	Source    string `json:"source"`
	EventKey  string `json:"event_key"`
	Status    string `json:"status"`
	Subject   string `json:"subject"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"created_at"`
	Emailed   bool   `json:"emailed"`
	Error     string `json:"error"`
}

func (s *Store) GetIntegrationState(source, eventKey string) (IntegrationState, error) {
	var state IntegrationState
	err := s.db.QueryRow(`SELECT source,event_key,status,subject,detail,first_seen,last_seen,last_notified
		FROM integration_state WHERE source=? AND event_key=?`, source, eventKey).
		Scan(&state.Source, &state.EventKey, &state.Status, &state.Subject, &state.Detail,
			&state.FirstSeen, &state.LastSeen, &state.LastNotified)
	return state, err
}

func (s *Store) ListIntegrationStates(source string) ([]IntegrationState, error) {
	rows, err := s.db.Query(`SELECT source,event_key,status,subject,detail,first_seen,last_seen,last_notified
		FROM integration_state WHERE source=? ORDER BY event_key`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []IntegrationState
	for rows.Next() {
		var state IntegrationState
		if err := rows.Scan(&state.Source, &state.EventKey, &state.Status, &state.Subject, &state.Detail,
			&state.FirstSeen, &state.LastSeen, &state.LastNotified); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (s *Store) UpsertIntegrationState(state IntegrationState) error {
	_, err := s.db.Exec(`INSERT INTO integration_state(source,event_key,status,subject,detail,first_seen,last_seen,last_notified)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(source,event_key) DO UPDATE SET
			status=excluded.status, subject=excluded.subject, detail=excluded.detail,
			last_seen=excluded.last_seen, last_notified=excluded.last_notified`,
		state.Source, state.EventKey, state.Status, state.Subject, state.Detail,
		state.FirstSeen, state.LastSeen, state.LastNotified)
	return err
}

func (s *Store) DeleteIntegrationState(source, eventKey string) error {
	_, err := s.db.Exec("DELETE FROM integration_state WHERE source=? AND event_key=?", source, eventKey)
	return err
}

func (s *Store) AddIntegrationEvent(event IntegrationEvent) error {
	emailed := 0
	if event.Emailed {
		emailed = 1
	}
	createdAt := event.CreatedAt
	if createdAt == "" {
		createdAt = crypto.Now()
	}
	_, err := s.db.Exec(`INSERT INTO integration_events(source,event_key,status,subject,detail,created_at,emailed,error)
		VALUES(?,?,?,?,?,?,?,?)`, event.Source, event.EventKey, event.Status, event.Subject,
		event.Detail, createdAt, emailed, event.Error)
	return err
}

func (s *Store) ListIntegrationEvents(limit int) ([]IntegrationEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,source,event_key,status,subject,detail,created_at,emailed,error
		FROM integration_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []IntegrationEvent
	for rows.Next() {
		var event IntegrationEvent
		var emailed int
		if err := rows.Scan(&event.ID, &event.Source, &event.EventKey, &event.Status, &event.Subject,
			&event.Detail, &event.CreatedAt, &emailed, &event.Error); err != nil {
			return nil, err
		}
		event.Emailed = emailed == 1
		events = append(events, event)
	}
	return events, rows.Err()
}
