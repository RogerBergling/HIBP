package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type keyEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	if len(s.keyDirs) == 0 {
		writeError(w, http.StatusBadRequest, "no SSH key directories are configured")
		return
	}
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		path = s.keyDirs[0]
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		writeError(w, http.StatusNotFound, "key directory not found")
		return
	}
	if !pathWithinRoots(resolved, s.keyDirs) {
		writeError(w, http.StatusForbidden, "path is outside the configured SSH key directories")
		return
	}
	info, err := os.Stat(resolved)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if !info.IsDir() {
		writeError(w, http.StatusBadRequest, "path is not a directory")
		return
	}
	dirEntries, err := os.ReadDir(resolved)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	entries := make([]keyEntry, 0, len(dirEntries))
	for _, entry := range dirEntries {
		entryPath := filepath.Join(resolved, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil {
			continue
		}
		if !entry.IsDir() && !entryInfo.Mode().IsRegular() {
			continue
		}
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".pub") {
			continue
		}
		entries = append(entries, keyEntry{
			Name:  entry.Name(),
			Path:  entryPath,
			IsDir: entry.IsDir(),
			Size:  entryInfo.Size(),
			Mode:  fmt.Sprintf("%04o", entryInfo.Mode().Perm()),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"path":    resolved,
		"roots":   s.keyDirs,
		"entries": entries,
	})
}

func pathWithinRoots(path string, roots []string) bool {
	for _, root := range roots {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(resolvedRoot, path)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
