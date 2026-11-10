// Package sshconfig reads concrete host entries from a local OpenSSH client
// configuration. It intentionally does not implement every OpenSSH directive;
// it resolves the fields HIBP needs to prefill a managed host.
package sshconfig

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Host is a concrete SSH config entry with its effective connection fields.
type Host struct {
	Alias         string   `json:"alias"`
	HostName      string   `json:"hostname"`
	Port          int      `json:"port"`
	User          string   `json:"user"`
	KeyPath       string   `json:"key_path"`
	IdentityFiles []string `json:"identity_files,omitempty"`
}

const (
	maxFileSize     = 1 << 20
	maxIncludeDepth = 8
	maxFiles        = 128
)

// Load reads a local OpenSSH client config. Relative Include and IdentityFile
// paths are resolved against ~/.ssh, matching the usual config location.
func Load(path string) ([]Host, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	return loadWithHome(path, home)
}

func loadWithHome(path, home string) ([]Host, error) {
	expanded, err := expandHome(path, home)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return nil, err
	}
	l := &loader{
		home:        home,
		sshDir:      filepath.Join(home, ".ssh"),
		defaultUser: currentUser(),
		seen:        make(map[string]bool),
		hosts:       make(map[string]*rawHost),
	}
	if err := l.loadFile(abs, 0); err != nil {
		return nil, err
	}
	return l.finalize(), nil
}

type loader struct {
	home        string
	sshDir      string
	defaultUser string
	seen        map[string]bool
	files       int
	hosts       map[string]*rawHost
}

type rawHost struct {
	hostName      string
	port          string
	user          string
	identityFiles []string
	setHostName   bool
	setPort       bool
	setUser       bool
	setIdentity   bool
}

type block struct {
	aliases       []string
	hostName      string
	port          string
	user          string
	identityFiles []string
	setHostName   bool
	setPort       bool
	setUser       bool
	setIdentity   bool
}

func (l *loader) loadFile(path string, depth int) error {
	if depth > maxIncludeDepth {
		return errors.New("too many nested SSH config includes")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if l.seen[abs] {
		return nil
	}
	l.seen[abs] = true
	l.files++
	if l.files > maxFiles {
		return errors.New("too many SSH config files")
	}
	info, err := os.Stat(abs)
	if err != nil {
		if depth > 0 && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("SSH config path is a directory: %s", abs)
	}
	if info.Size() > maxFileSize {
		return fmt.Errorf("SSH config file is too large: %s", abs)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	return l.parse(string(data), depth)
}

func (l *loader) parse(data string, depth int) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	var current *block
	inMatch := false
	finalize := func() {
		if current != nil {
			l.merge(current)
			current = nil
		}
	}
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		key, value := splitDirective(line)
		switch strings.ToLower(key) {
		case "host":
			finalize()
			inMatch = false
			current = &block{aliases: concretePatterns(value)}
			if len(current.aliases) == 0 {
				current = nil
			}
		case "match":
			finalize()
			inMatch = true
		case "include":
			if !inMatch {
				if err := l.processInclude(value, depth); err != nil {
					return err
				}
			}
		default:
			if inMatch || current == nil {
				continue
			}
			switch strings.ToLower(key) {
			case "hostname":
				if !current.setHostName {
					current.hostName = unquote(value)
					current.setHostName = true
				}
			case "port":
				if !current.setPort {
					current.port = unquote(value)
					current.setPort = true
				}
			case "user":
				if !current.setUser {
					current.user = unquote(value)
					current.setUser = true
				}
			case "identityfile":
				current.identityFiles = append(current.identityFiles, unquote(value))
				current.setIdentity = true
			}
		}
	}
	finalize()
	return scanner.Err()
}

func (l *loader) merge(b *block) {
	for _, alias := range b.aliases {
		existing := l.hosts[alias]
		if existing == nil {
			existing = &rawHost{}
			l.hosts[alias] = existing
		}
		if !existing.setHostName && b.setHostName {
			existing.hostName = b.hostName
			existing.setHostName = true
		}
		if !existing.setPort && b.setPort {
			existing.port = b.port
			existing.setPort = true
		}
		if !existing.setUser && b.setUser {
			existing.user = b.user
			existing.setUser = true
		}
		if !existing.setIdentity && b.setIdentity {
			existing.identityFiles = append([]string(nil), b.identityFiles...)
			existing.setIdentity = true
		}
	}
}

func (l *loader) finalize() []Host {
	aliases := make([]string, 0, len(l.hosts))
	for alias := range l.hosts {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	hosts := make([]Host, 0, len(aliases))
	for _, alias := range aliases {
		raw := l.hosts[alias]
		hostName := raw.hostName
		if hostName == "" {
			hostName = alias
		}
		port := 22
		if parsed, err := strconv.Atoi(raw.port); err == nil && parsed >= 1 && parsed <= 65535 {
			port = parsed
		}
		remoteUser := raw.user
		if remoteUser == "" {
			remoteUser = l.defaultUser
		}
		identityFiles := make([]string, 0, len(raw.identityFiles))
		seen := make(map[string]bool)
		for _, file := range raw.identityFiles {
			expanded := l.expandIdentity(file, remoteUser, hostName)
			if expanded == "" || seen[expanded] {
				continue
			}
			seen[expanded] = true
			identityFiles = append(identityFiles, expanded)
		}
		keyPath := ""
		if len(identityFiles) > 0 {
			keyPath = identityFiles[0]
		} else {
			keyPath = firstDefaultKey(l.sshDir)
		}
		hosts = append(hosts, Host{
			Alias:         alias,
			HostName:      hostName,
			Port:          port,
			User:          remoteUser,
			KeyPath:       keyPath,
			IdentityFiles: identityFiles,
		})
	}
	return hosts
}

func (l *loader) expandIdentity(value, remoteUser, hostName string) string {
	value = unquote(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "%d", l.home)
	value = strings.ReplaceAll(value, "%u", remoteUser)
	value = strings.ReplaceAll(value, "%r", remoteUser)
	value = strings.ReplaceAll(value, "%h", hostName)
	expanded, err := expandHome(value, l.home)
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(l.sshDir, expanded)
	}
	return filepath.Clean(expanded)
}

func (l *loader) processInclude(value string, depth int) error {
	for _, pattern := range strings.Fields(value) {
		pattern = unquote(pattern)
		if pattern == "" {
			continue
		}
		expanded, err := expandHome(pattern, l.home)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(expanded) {
			expanded = filepath.Join(l.sshDir, expanded)
		}
		matches, err := filepath.Glob(expanded)
		if err != nil {
			return fmt.Errorf("invalid SSH config include %q: %w", pattern, err)
		}
		sort.Strings(matches)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			if info.IsDir() {
				continue
			}
			if err := l.loadFile(match, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func concretePatterns(value string) []string {
	fields := strings.Fields(value)
	patterns := make([]string, 0, len(fields))
	for _, field := range fields {
		field = unquote(field)
		if field == "" || strings.HasPrefix(field, "!") || strings.ContainsAny(field, "*?") {
			continue
		}
		patterns = append(patterns, field)
	}
	return patterns
}

func splitDirective(line string) (string, string) {
	index := strings.IndexAny(line, " \t=")
	if index < 0 {
		return line, ""
	}
	key := line[:index]
	value := strings.TrimSpace(line[index:])
	value = strings.TrimSpace(strings.TrimPrefix(value, "="))
	return key, value
}

func stripComment(line string) string {
	inQuote := false
	for index := 0; index < len(line); index++ {
		switch line[index] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:index]
			}
		}
	}
	return line
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func expandHome(value, home string) (string, error) {
	if value == "~" {
		return home, nil
	}
	if strings.HasPrefix(value, "~/") {
		return filepath.Join(home, value[2:]), nil
	}
	return value, nil
}

func currentUser() string {
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return os.Getenv("USER")
}

func firstDefaultKey(sshDir string) string {
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		path := filepath.Join(sshDir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}
