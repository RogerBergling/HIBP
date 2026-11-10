package server

import (
	"errors"
	"net/http"
	"os"

	"github.com/RogerBergling/hibp/internal/sshconfig"
)

func (s *Server) handleSSHConfig(w http.ResponseWriter, _ *http.Request) {
	hosts, err := sshconfig.Load(s.sshConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusOK, map[string]any{
			"path":   s.sshConfigPath,
			"exists": false,
			"hosts":  []sshconfig.Host{},
		})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []sshconfig.Host{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":   s.sshConfigPath,
		"exists": true,
		"hosts":  hosts,
	})
}
