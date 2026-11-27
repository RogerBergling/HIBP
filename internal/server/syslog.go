package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

type syslogMessage struct {
	Facility  int
	Severity  int
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcID    string
	Message   string
}

// RunSyslog supervises the configurable syslog receiver. UDM pushes messages;
// HIBP never connects back to the device.
func (s *Server) RunSyslog(ctx context.Context) {
	var cancel context.CancelFunc
	current := ""
	check := func() {
		enabled := s.store.ResolveSetting("", "syslog.enabled", "0") == "1"
		listen := strings.TrimSpace(s.store.ResolveSetting("", "syslog.listen", "0.0.0.0:5514"))
		protocol := strings.ToLower(strings.TrimSpace(s.store.ResolveSetting("", "syslog.protocol", "udp")))
		key := fmt.Sprintf("%t|%s|%s", enabled, listen, protocol)
		if key == current {
			return
		}
		if cancel != nil {
			cancel()
			cancel = nil
		}
		current = key
		if !enabled {
			slog.Info("syslog: receiver disabled")
			return
		}
		listenerCtx, listenerCancel := context.WithCancel(ctx)
		cancel = listenerCancel
		slog.Info("syslog: receiver starting", "listen", listen, "protocol", protocol)
		go s.runSyslogListener(listenerCtx, listen, protocol)
	}
	check()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
			}
			return
		case <-ticker.C:
			check()
		}
	}
}

func (s *Server) runSyslogListener(ctx context.Context, listen, protocol string) {
	switch protocol {
	case "tcp":
		s.runSyslogTCP(ctx, listen)
	default:
		s.runSyslogUDP(ctx, listen)
	}
}

func (s *Server) runSyslogUDP(ctx context.Context, listen string) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		slog.Warn("syslog: resolve UDP address", "listen", listen, "error", err)
		return
	}
	for {
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			slog.Warn("syslog: listen UDP", "listen", listen, "error", err)
			if !waitSyslogRetry(ctx) {
				return
			}
			continue
		}
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
		buffer := make([]byte, 16<<10)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if ctx.Err() == nil {
					slog.Warn("syslog: read UDP", "error", err)
				}
				return
			}
			line := strings.TrimSpace(string(buffer[:n]))
			if line == "" {
				continue
			}
			for _, entry := range strings.Split(line, "\n") {
				entry = strings.TrimSpace(entry)
				if entry != "" {
					s.handleSyslogMessage(source.IP.String(), entry)
				}
			}
		}
	}
}

func (s *Server) runSyslogTCP(ctx context.Context, listen string) {
	for {
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			slog.Warn("syslog: listen TCP", "listen", listen, "error", err)
			if !waitSyslogRetry(ctx) {
				return
			}
			continue
		}
		go func() {
			<-ctx.Done()
			_ = listener.Close()
		}()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					slog.Warn("syslog: accept TCP", "error", err)
				}
				return
			}
			go s.handleSyslogConnection(ctx, conn)
		}
	}
}

func waitSyslogRetry(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(10 * time.Second):
		return true
	}
}

func (s *Server) handleSyslogConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	sourceIP := ""
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		sourceIP = host
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			s.handleSyslogMessage(sourceIP, line)
		}
	}
}

func (s *Server) handleSyslogMessage(sourceIP, line string) {
	msg, err := parseSyslogMessage(line, time.Now())
	if err != nil {
		return
	}
	host, ok := s.networkHostForSource(sourceIP)
	if !ok {
		return
	}
	category, severity := syslogEventClass(msg)
	message := strings.TrimSpace(msg.Message)
	if msg.AppName != "" {
		message = msg.AppName + ": " + message
	}
	if len(message) > 512 {
		message = message[:512]
	}
	event := store.HostEvent{
		EventID:    syslogEventID(sourceIP, msg),
		Source:     "syslog",
		Category:   category,
		Severity:   severity,
		RemoteIP:   sourceIP,
		Message:    message,
		OccurredAt: msg.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	if err := s.store.AddHostEvents(host.ID, []store.HostEvent{event}); err != nil {
		slog.Warn("syslog: store event", "host", host.Name, "error", err)
	}
}

func (s *Server) networkHostForSource(sourceIP string) (store.Host, bool) {
	normalized := sourceIP
	if parsed := net.ParseIP(sourceIP); parsed != nil {
		normalized = parsed.String()
	}
	s.networkHostsMu.Lock()
	defer s.networkHostsMu.Unlock()
	if s.networkHosts == nil || time.Since(s.networkHostsAt) > 30*time.Second {
		hosts, err := s.store.ListHosts()
		if err == nil {
			cache := make(map[string]store.Host)
			for _, host := range hosts {
				if host.AuthType != "network" {
					continue
				}
				if parsed := net.ParseIP(host.Address); parsed != nil {
					cache[parsed.String()] = host
				}
				sources, _ := parseIPList(s.store.ResolveSetting(host.ID, "syslog.sources", ""))
				for _, source := range sources {
					if parsed := net.ParseIP(source); parsed != nil {
						cache[parsed.String()] = host
					}
				}
			}
			s.networkHosts = cache
			s.networkHostsAt = time.Now()
		}
	}
	host, ok := s.networkHosts[normalized]
	return host, ok
}

func parseSyslogMessage(line string, now time.Time) (syslogMessage, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return syslogMessage{}, errors.New("empty syslog message")
	}
	if line[0] != '<' {
		return syslogMessage{}, errors.New("missing syslog priority")
	}
	end := strings.IndexByte(line, '>')
	if end < 1 {
		return syslogMessage{}, errors.New("invalid syslog priority")
	}
	priority, err := strconv.Atoi(line[1:end])
	if err != nil || priority < 0 || priority > 191 {
		return syslogMessage{}, errors.New("invalid syslog priority")
	}
	msg := syslogMessage{
		Facility:  priority / 8,
		Severity:  priority % 8,
		Timestamp: now,
	}
	rest := strings.TrimSpace(line[end+1:])
	if rest == "" {
		return msg, nil
	}
	if len(rest) > 2 && rest[0] >= '1' && rest[0] <= '9' && rest[1] == ' ' {
		parseRFC5424(rest, &msg)
	} else {
		parseRFC3164(rest, &msg, now)
	}
	return msg, nil
}

func parseRFC5424(rest string, msg *syslogMessage) {
	fields := strings.SplitN(rest, " ", 7)
	if len(fields) < 7 {
		msg.Message = rest
		return
	}
	if fields[1] != "-" {
		if parsed, err := time.Parse(time.RFC3339Nano, fields[1]); err == nil {
			msg.Timestamp = parsed
		}
	}
	msg.Hostname = dashValue(fields[2])
	msg.AppName = dashValue(fields[3])
	msg.ProcID = dashValue(fields[4])
	msg.Message = parseStructuredData(fields[6])
}

func parseRFC3164(rest string, msg *syslogMessage, now time.Time) {
	fields := strings.SplitN(rest, " ", 5)
	if len(fields) < 4 {
		msg.Message = rest
		return
	}
	stamp := strings.Join(fields[:3], " ")
	if parsed, err := time.ParseInLocation("Jan 2 15:04:05", stamp, now.Location()); err == nil {
		parsed = parsed.AddDate(now.Year(), 0, 0)
		if parsed.After(now.Add(24 * time.Hour)) {
			parsed = parsed.AddDate(-1, 0, 0)
		}
		msg.Timestamp = parsed
	}
	msg.Hostname = fields[3]
	tag := fields[4]
	msg.Message = tag
	if index := strings.Index(tag, ":"); index >= 0 {
		app := strings.TrimSpace(tag[:index])
		if bracket := strings.IndexByte(app, '['); bracket > 0 {
			app = app[:bracket]
		}
		msg.AppName = app
		msg.Message = strings.TrimSpace(tag[index+1:])
	}
}

func parseStructuredData(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if value[0] == '-' {
		return strings.TrimSpace(value[1:])
	}
	if value[0] != '[' {
		return value
	}
	depth := 0
	escaped := false
	for index, char := range value {
		if escaped {
			escaped = false
			continue
		}
		switch char {
		case '\\':
			escaped = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return strings.TrimSpace(value[index+1:])
			}
		}
	}
	return value
}

func dashValue(value string) string {
	if value == "-" {
		return ""
	}
	return value
}

func syslogEventClass(msg syslogMessage) (string, string) {
	lower := strings.ToLower(msg.AppName + " " + msg.Message)
	severity := "info"
	switch {
	case msg.Severity <= 2:
		severity = "critical"
	case msg.Severity <= 4:
		severity = "warning"
	}
	switch {
	case containsAny(lower, "authentication failure", "auth failure", "failed password", "invalid user", "login failed", "radius", "802.1x"):
		return "auth_failure", "warning"
	case containsAny(lower, "wan", "pppoe", "failover") && containsAny(lower, "down", "up", "fail", "disconnect", "connect", "lost"):
		if containsAny(lower, "down", "fail", "disconnect", "lost") {
			return "network_wan", "critical"
		}
		return "network_wan", "warning"
	case containsAny(lower, "link", "port", "interface", "stp") && containsAny(lower, "down", "up", "fail", "error"):
		return "network_link", "warning"
	case containsAny(lower, "access point", "ap ", "adopt", "disconnect", "roam", "ssid", "wifi"):
		return "network_wifi", severity
	case containsAny(lower, "firmware", "upgrade", "reboot", "config change", "configuration", "restart"):
		return "system", severity
	}
	if msg.Facility == 4 || msg.Facility == 10 {
		return "auth", severity
	}
	return "syslog", severity
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func syslogEventID(sourceIP string, msg syslogMessage) string {
	sum := sha256.Sum256([]byte(sourceIP + "\x00" + msg.Timestamp.UTC().Format(time.RFC3339Nano) +
		"\x00" + msg.AppName + "\x00" + msg.Message))
	return "syslog-" + hex.EncodeToString(sum[:12])
}
