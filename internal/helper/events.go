package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event is a bounded, normalized monitoring event collected from the target.
// Raw journal payloads are not returned to the controller.
type Event struct {
	EventID    string `json:"event_id"`
	Source     string `json:"source"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Unit       string `json:"unit,omitempty"`
	Username   string `json:"username,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	Message    string `json:"message,omitempty"`
	OccurredAt string `json:"occurred_at"`
}

var (
	failedPasswordPattern  = regexp.MustCompile(`(?i)failed password for (?:invalid user )?([^ ]+) from ([0-9a-f:.]+)`)
	failedPublicKeyPattern = regexp.MustCompile(`(?i)failed publickey for (?:invalid user )?([^ ]+) from ([0-9a-f:.]+)`)
	invalidUserPattern     = regexp.MustCompile(`(?i)invalid user ([^ ]+) from ([0-9a-f:.]+)`)
	sudoUserPattern        = regexp.MustCompile(`(?i)\buser=([^ ]+)`)
)

func collectEvents(ctx context.Context) ([]Event, error) {
	events := collectJournalEvents(ctx)
	if len(events) == 0 {
		events = collectAuthFileEvents()
	}
	if len(events) > 200 {
		events = events[len(events)-200:]
	}
	return events, nil
}

func collectJournalEvents(ctx context.Context) []Event {
	if _, err := lookPath("journalctl"); err != nil {
		return nil
	}
	output, code, err := runBinary(ctx, "journalctl", "-o", "json", "--no-pager", "--quiet", "--since", "15 min ago", "-n", "500")
	if err != nil || code != 0 {
		return nil
	}
	var events []Event
	seen := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		event, ok := parseJournalEvent(line)
		if !ok || seen[event.EventID] {
			continue
		}
		seen[event.EventID] = true
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].OccurredAt < events[j].OccurredAt })
	return events
}

func parseJournalEvent(line string) (Event, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Event{}, false
	}
	message := journalString(raw["MESSAGE"])
	if message == "" {
		return Event{}, false
	}
	unit := journalString(raw["_SYSTEMD_UNIT"])
	identifier := journalString(raw["SYSLOG_IDENTIFIER"])
	comm := journalString(raw["_COMM"])
	source := unit
	if source == "" {
		source = identifier
	}
	if source == "" {
		source = comm
	}
	category, severity := classifyEvent(message, unit, identifier)
	if category == "" {
		return Event{}, false
	}
	username, remoteIP := eventIdentity(message)
	occurred := journalTimestamp(raw["__REALTIME_TIMESTAMP"])
	cursor := journalString(raw["__CURSOR"])
	if cursor == "" {
		cursor = hashEvent(source, occurred, message)
	}
	return Event{
		EventID: cursor, Source: source, Category: category, Severity: severity,
		Unit: unit, Username: username, RemoteIP: remoteIP,
		Message: truncateEventMessage(message), OccurredAt: occurred,
	}, true
}

func journalString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return strings.TrimSpace(value)
	}
	var values []any
	if err := json.Unmarshal(raw, &values); err == nil {
		var builder strings.Builder
		for _, item := range values {
			switch typed := item.(type) {
			case float64:
				builder.WriteByte(byte(typed))
			case string:
				builder.WriteString(typed)
			}
		}
		return strings.TrimSpace(builder.String())
	}
	return ""
}

func journalTimestamp(raw json.RawMessage) string {
	value := journalString(raw)
	if microseconds, err := strconv.ParseInt(value, 10, 64); err == nil && microseconds > 0 {
		return time.Unix(0, microseconds*1000).UTC().Format(time.RFC3339Nano)
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func classifyEvent(message, unit, identifier string) (string, string) {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "failed password"),
		strings.Contains(lower, "failed publickey"),
		strings.Contains(lower, "authentication failure"),
		strings.Contains(lower, "invalid user"),
		strings.Contains(lower, "incorrect password"),
		strings.Contains(lower, "sorry, try again"):
		return "auth_failure", "warning"
	case strings.Contains(lower, "out of memory"),
		strings.Contains(lower, "oom-kill"),
		strings.Contains(lower, "killed process"):
		return "oom", "critical"
	case strings.Contains(lower, "failed with result"),
		strings.Contains(lower, "entered failed state"),
		strings.Contains(lower, "failed to start"),
		strings.Contains(lower, "start request repeated too quickly"):
		return "service_failure", "critical"
	case (strings.Contains(strings.ToLower(unit), "chrony") ||
		strings.Contains(strings.ToLower(unit), "timesyncd") ||
		strings.Contains(strings.ToLower(identifier), "chrony") ||
		strings.Contains(strings.ToLower(identifier), "timesyncd")) &&
		(strings.Contains(lower, "synchron") || strings.Contains(lower, "clock") ||
			strings.Contains(lower, "offset") || strings.Contains(lower, "step")):
		return "ntp", "warning"
	}
	return "", ""
}

func eventIdentity(message string) (string, string) {
	for _, pattern := range []*regexp.Regexp{failedPasswordPattern, failedPublicKeyPattern, invalidUserPattern} {
		if matches := pattern.FindStringSubmatch(message); len(matches) == 3 {
			return matches[1], matches[2]
		}
	}
	if matches := sudoUserPattern.FindStringSubmatch(message); len(matches) == 2 {
		return matches[1], ""
	}
	return "", ""
}

func collectAuthFileEvents() []Event {
	var events []Event
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		if len(data) > 64<<10 {
			data = data[len(data)-64<<10:]
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			category, severity := classifyEvent(line, "", "")
			if category != "auth_failure" {
				continue
			}
			username, remoteIP := eventIdentity(line)
			events = append(events, Event{
				EventID: hashEvent(path, line), Source: path,
				Category: category, Severity: severity,
				Username: username, RemoteIP: remoteIP,
				Message: truncateEventMessage(line), OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
	}
	if len(events) > 200 {
		events = events[len(events)-200:]
	}
	return events
}

func hashEvent(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func truncateEventMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) <= 512 {
		return message
	}
	return message[:512]
}
