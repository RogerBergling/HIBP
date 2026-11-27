package store

import (
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
)

// SNMPValue is the latest collected value for one OID on a network host.
type SNMPValue struct {
	HostID      string `json:"host_id"`
	OID         string `json:"oid"`
	Value       string `json:"value"`
	ValueType   string `json:"value_type"`
	CollectedAt string `json:"collected_at"`
}

// SNMPPollState records the last SNMP poll attempt for a host. LastError is
// empty after a successful poll and contains the bounded failure reason
// otherwise. Previous values are retained after a failed poll.
type SNMPPollState struct {
	HostID    string `json:"host_id"`
	LastPoll  string `json:"last_poll"`
	LastError string `json:"last_error"`
}

func (s *Store) SaveSNMPValues(hostID, collectedAt string, values []SNMPValue) error {
	if strings.TrimSpace(hostID) == "" || strings.TrimSpace(collectedAt) == "" {
		return errors.New("host id and collected time are required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM snmp_values WHERE host_id=?", hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, value := range values {
		oid := strings.TrimSpace(value.OID)
		if oid == "" {
			continue
		}
		valueType := strings.TrimSpace(value.ValueType)
		if valueType == "" {
			valueType = "string"
		}
		if _, err := tx.Exec(`INSERT INTO snmp_values(host_id,oid,value,value_type,collected_at)
			VALUES(?,?,?,?,?)
			ON CONFLICT(host_id,oid) DO UPDATE SET
				value=excluded.value, value_type=excluded.value_type, collected_at=excluded.collected_at`,
			hostID, oid, value.Value, valueType, collectedAt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListSNMPValues(hostID string) ([]SNMPValue, error) {
	rows, err := s.db.Query(`SELECT host_id,oid,value,value_type,collected_at
		FROM snmp_values WHERE host_id=? ORDER BY oid`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []SNMPValue
	for rows.Next() {
		var value SNMPValue
		if err := rows.Scan(&value.HostID, &value.OID, &value.Value, &value.ValueType, &value.CollectedAt); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) GetSNMPValue(hostID, oid string) (SNMPValue, error) {
	var value SNMPValue
	err := s.db.QueryRow(`SELECT host_id,oid,value,value_type,collected_at
		FROM snmp_values WHERE host_id=? AND oid=?`, hostID, oid).
		Scan(&value.HostID, &value.OID, &value.Value, &value.ValueType, &value.CollectedAt)
	return value, err
}

func (s *Store) SetSNMPPollState(hostID, lastPoll, lastError string) error {
	if strings.TrimSpace(hostID) == "" {
		return errors.New("host id is required")
	}
	if strings.TrimSpace(lastPoll) == "" {
		lastPoll = crypto.Now()
	}
	_, err := s.db.Exec(`INSERT INTO snmp_poll_state(host_id,last_poll,last_error)
		VALUES(?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET last_poll=excluded.last_poll, last_error=excluded.last_error`,
		hostID, lastPoll, lastError)
	return err
}

func (s *Store) GetSNMPPollState(hostID string) (SNMPPollState, error) {
	var state SNMPPollState
	err := s.db.QueryRow(`SELECT host_id,last_poll,last_error FROM snmp_poll_state WHERE host_id=?`, hostID).
		Scan(&state.HostID, &state.LastPoll, &state.LastError)
	return state, err
}
