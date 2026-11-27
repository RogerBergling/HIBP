package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

type Agent struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	Name      string `json:"name"`
	TokenHash string `json:"-"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	LastSeen  string `json:"last_seen"`
	CreatedAt string `json:"created_at"`
	RevokedAt string `json:"revoked_at"`
}

func (s *Store) CreateAgent(hostID, name, tokenHash string) (Agent, error) {
	hostID = strings.TrimSpace(hostID)
	name = strings.TrimSpace(name)
	tokenHash = strings.TrimSpace(tokenHash)
	if hostID == "" || name == "" || tokenHash == "" {
		return Agent{}, errors.New("host, name, and token hash are required")
	}
	agent := Agent{
		ID: uuid.NewString(), HostID: hostID, Name: name, TokenHash: tokenHash,
		CreatedAt: crypto.Now(),
	}
	_, err := s.db.Exec(`INSERT INTO agents(id,host_id,name,token_hash,created_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET
			name=excluded.name, token_hash=excluded.token_hash, revoked_at=''`,
		agent.ID, agent.HostID, agent.Name, agent.TokenHash, agent.CreatedAt)
	if err != nil {
		return Agent{}, err
	}
	return s.GetAgentByHost(hostID)
}

func (s *Store) GetAgentByHost(hostID string) (Agent, error) {
	var agent Agent
	err := s.db.QueryRow(`SELECT id,host_id,name,token_hash,platform,version,last_seen,created_at,revoked_at
		FROM agents WHERE host_id=?`, hostID).Scan(&agent.ID, &agent.HostID, &agent.Name,
		&agent.TokenHash, &agent.Platform, &agent.Version, &agent.LastSeen, &agent.CreatedAt, &agent.RevokedAt)
	return agent, err
}

func (s *Store) GetAgentByTokenHash(tokenHash string) (Agent, error) {
	var agent Agent
	err := s.db.QueryRow(`SELECT id,host_id,name,token_hash,platform,version,last_seen,created_at,revoked_at
		FROM agents WHERE token_hash=? AND revoked_at=''`, tokenHash).Scan(&agent.ID, &agent.HostID, &agent.Name,
		&agent.TokenHash, &agent.Platform, &agent.Version, &agent.LastSeen, &agent.CreatedAt, &agent.RevokedAt)
	return agent, err
}

func (s *Store) TouchAgent(id, platform, version string) error {
	if _, err := s.db.Exec(`UPDATE agents SET platform=?, version=?, last_seen=? WHERE id=?`,
		strings.TrimSpace(platform), strings.TrimSpace(version), crypto.Now(), id); err != nil {
		return err
	}
	return nil
}

func (s *Store) RevokeAgent(hostID string) error {
	result, err := s.db.Exec(`UPDATE agents SET revoked_at=? WHERE host_id=? AND revoked_at=''`, crypto.Now(), hostID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
