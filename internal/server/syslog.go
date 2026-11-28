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
	"regexp"
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
	CEF       *cefEvent
}

// cefEvent is a bounded view of an ArcSight Common Event Format message. The
// raw message remains the source of truth; CEF fields are used to classify the
// event and enrich the stored identity.
type cefEvent struct {
	Version       string
	Vendor        string
	Product       string
	DeviceVersion string
	EventID       string
	Name          string
	Severity      int
	Extensions    map[string]string
}

const (
	syslogMessageLimit = 4096
	cefValueLimit      = 1024
)

var cefExtensionKey = regexp.MustCompile(`(^| )([A-Za-z0-9_.-]+)=`)
var qnapUserPattern = regexp.MustCompile(`(?i)\bUsers?:\s*([^,]+)`)
var qnapSourcePattern = regexp.MustCompile(`(?i)\bSource IP:\s*([0-9a-f:.]+)`)

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
		s.logSyslogDiagnostic(sourceIP, "invalid message: "+err.Error())
		return
	}
	host, ok := s.networkHostForSource(sourceIP)
	if !ok {
		s.logSyslogDiagnostic(sourceIP, "unmapped source")
		return
	}
	category, severity := syslogEventClass(msg)
	message := strings.TrimSpace(msg.Message)
	if msg.AppName != "" {
		message = msg.AppName + ": " + message
	}
	if len(message) > syslogMessageLimit {
		message = message[:syslogMessageLimit]
	}
	decision := s.evaluateSyslogPolicy(host.ID, message, category, severity)
	username := ""
	remoteIP := sourceIP
	if msg.CEF != nil {
		username = truncateEventField(msg.CEF.firstExtension("suser", "duser", "unifi_user",
			"unifi_username", "username", "user"), 128)
		if value := msg.CEF.firstExtension("src", "source", "unificlientip", "clientip"); value != "" {
			remoteIP = truncateEventField(value, 64)
		}
	}
	if username == "" {
		if match := qnapUserPattern.FindStringSubmatch(message); len(match) == 2 {
			username = truncateEventField(strings.TrimSpace(match[1]), 128)
		}
	}
	if match := qnapSourcePattern.FindStringSubmatch(message); len(match) == 2 {
		remoteIP = truncateEventField(strings.TrimSpace(match[1]), 64)
	}
	event := store.HostEvent{
		EventID:          syslogEventID(sourceIP, msg),
		Source:           "syslog",
		Category:         decision.Category,
		Severity:         decision.Severity,
		Username:         username,
		RemoteIP:         remoteIP,
		Message:          message,
		OccurredAt:       msg.Timestamp.UTC().Format(time.RFC3339Nano),
		OriginalCategory: category,
		OriginalSeverity: severity,
		PolicyID:         decision.PolicyID,
		PolicyName:       decision.PolicyName,
		Suppressed:       decision.Suppressed,
		Guardrail:        decision.Guardrail,
	}
	if err := s.store.AddHostEvents(host.ID, []store.HostEvent{event}); err != nil {
		slog.Warn("syslog: store event", "host", host.Name, "error", err)
		return
	}
	s.logSyslogAccepted(sourceIP, host.Name, decision.Category)
}

func (s *Server) logSyslogAccepted(source, host, category string) {
	s.syslogWarnMu.Lock()
	key := source + "|accepted|" + host
	if last, ok := s.syslogWarnAt[key]; ok && time.Since(last) < time.Minute {
		s.syslogWarnMu.Unlock()
		return
	}
	if len(s.syslogWarnAt) > 1000 {
		s.syslogWarnAt = make(map[string]time.Time)
	}
	s.syslogWarnAt[key] = time.Now()
	s.syslogWarnMu.Unlock()
	slog.Info("syslog: accepted event", "host", host, "source", source, "category", category)
}

// logSyslogDiagnostic reports an unmapped source or invalid message at most
// once per minute per source and issue. This makes syslog delivery problems
// visible without allowing a noisy or spoofed source to flood the log.
func (s *Server) logSyslogDiagnostic(source, issue string) {
	s.syslogWarnMu.Lock()
	if s.syslogWarnAt == nil {
		s.syslogWarnAt = make(map[string]time.Time)
	}
	key := source + "|" + issue
	if last, ok := s.syslogWarnAt[key]; ok && time.Since(last) < time.Minute {
		s.syslogWarnMu.Unlock()
		return
	}
	if len(s.syslogWarnAt) > 1000 {
		s.syslogWarnAt = make(map[string]time.Time)
	}
	s.syslogWarnAt[key] = time.Now()
	s.syslogWarnMu.Unlock()
	slog.Warn("syslog: "+issue, "source", source)
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
		// Some appliances send RFC3164-like or structured messages without a
		// leading priority. The source is already restricted to a network host,
		// so keep the bounded text as an informational event instead of dropping
		// it silently.
		return syslogMessage{Severity: 6, Timestamp: now, Message: line, CEF: parseCEF(line)}, nil
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
	// Appliances may prefix CEF with an RFC3164 tag, which would otherwise
	// turn "CEF:0|..." into app "CEF" and message "0|...". Parse from the raw
	// line as a fallback and keep the complete CEF payload in the message.
	cef := parseCEF(msg.Message)
	if cef == nil {
		cef = parseCEF(line)
	}
	if cef != nil {
		msg.CEF = cef
		if index := strings.Index(line, "CEF:"); index >= 0 {
			msg.Message = strings.TrimSpace(line[index:])
			if strings.EqualFold(msg.AppName, "CEF") {
				msg.AppName = ""
			}
		}
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
	if msg.CEF == nil {
		msg.CEF = parseCEF(msg.Message)
	}
	if msg.CEF != nil {
		return cefEventClass(msg.CEF)
	}
	lower := strings.ToLower(msg.AppName + " " + msg.Message)
	severity := "info"
	switch {
	case msg.Severity <= 2:
		severity = "critical"
	case msg.Severity <= 4:
		severity = "warning"
	}
	switch {
	case (containsAny(lower, "radius") && containsAny(lower, "fail", "reject", "denied", "invalid", "timeout", "unreachable")) ||
		(containsAny(lower, "802.1x") && containsAny(lower, "fail", "reject", "denied", "invalid", "timeout")):
		return "auth_failure", "critical"
	case containsAny(lower, "authentication failure", "auth failure", "failed password", "invalid user", "login failed", "login fail"):
		return "auth_failure", "critical"
	case containsAny(lower, "wan", "pppoe", "failover") && containsAny(lower, "down", "up", "fail", "disconnect", "connect", "lost"):
		if containsAny(lower, "down", "fail", "disconnect", "lost") {
			return "network_wan", "critical"
		}
		return "network_wan", "warning"
	case containsAny(lower, "link", "port", "interface", "stp") && containsAny(lower, "down", "up", "fail", "error"):
		return "network_link", "warning"
	case containsAny(lower, "access point", "ap ", "adopt", "disconnect", "roam", "ssid", "wifi", "hostapd"):
		return "network_wifi", severity
	case containsAny(lower, "mc2uc", "sta_cnt["):
		// MediaTek/Ralink driver multicast-to-unicast diagnostics are periodic
		// counters, not warnings, even when the AP sends them with a warning PRI.
		return "network_wifi", "info"
	case containsAny(lower, "firmware", "upgrade", "reboot", "config change", "configuration", "restart"):
		return "system", severity
	}
	if msg.Facility == 4 || msg.Facility == 10 {
		return "auth", severity
	}
	return "syslog", severity
}

// parseCEF extracts the bounded header and extension fields from an ArcSight
// CEF message. Appliances may prefix CEF with a syslog timestamp and hostname,
// so the marker is located rather than required at the start of the message.
func parseCEF(message string) *cefEvent {
	index := strings.Index(message, "CEF:")
	if index < 0 {
		return nil
	}
	if index > 0 {
		previous := message[index-1]
		if previous != ' ' && previous != '\t' && previous != '[' {
			return nil
		}
	}
	rest := message[index+4:]
	fields := make([]string, 0, 7)
	for len(fields) < 7 {
		value, remainder, ok := cutCEFField(rest)
		if !ok {
			return nil
		}
		fields = append(fields, value)
		rest = remainder
	}
	severity, err := strconv.Atoi(strings.TrimSpace(fields[6]))
	if err != nil {
		return nil
	}
	if severity < 0 {
		severity = 0
	}
	if severity > 10 {
		severity = 10
	}
	return &cefEvent{
		Version:       fields[0],
		Vendor:        fields[1],
		Product:       fields[2],
		DeviceVersion: fields[3],
		EventID:       fields[4],
		Name:          fields[5],
		Severity:      severity,
		Extensions:    parseCEFExtensions(rest),
	}
}

func cutCEFField(value string) (string, string, bool) {
	var builder strings.Builder
	escaped := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if escaped {
			builder.WriteByte(char)
			escaped = false
			continue
		}
		switch char {
		case '\\':
			escaped = true
		case '|':
			return builder.String(), value[index+1:], true
		default:
			builder.WriteByte(char)
		}
	}
	return "", "", false
}

func parseCEFExtensions(value string) map[string]string {
	matches := cefExtensionKey.FindAllStringSubmatchIndex(value, 128)
	if len(matches) == 0 {
		return nil
	}
	extensions := make(map[string]string, len(matches))
	for index, match := range matches {
		if len(match) < 6 {
			continue
		}
		key := strings.ToLower(value[match[4]:match[5]])
		start := match[1]
		end := len(value)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		item := strings.TrimSpace(value[start:end])
		if len(item) > cefValueLimit {
			item = item[:cefValueLimit]
		}
		if _, exists := extensions[key]; !exists {
			extensions[key] = unescapeCEF(item)
		}
	}
	return extensions
}

func unescapeCEF(value string) string {
	if !strings.Contains(value, "\\") {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value))
	escaped := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if escaped {
			switch char {
			case 'n':
				builder.WriteByte('\n')
			case 'r':
				builder.WriteByte('\r')
			default:
				builder.WriteByte(char)
			}
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		builder.WriteByte(char)
	}
	if escaped {
		builder.WriteByte('\\')
	}
	return builder.String()
}

func (cef *cefEvent) firstExtension(keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(cef.Extensions[strings.ToLower(key)])
		if value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func (cef *cefEvent) searchable() string {
	var builder strings.Builder
	builder.WriteString(strings.ToLower(cef.Vendor))
	builder.WriteByte(' ')
	builder.WriteString(strings.ToLower(cef.Product))
	builder.WriteByte(' ')
	builder.WriteString(strings.ToLower(cef.EventID))
	builder.WriteByte(' ')
	builder.WriteString(strings.ToLower(cef.Name))
	for key, value := range cef.Extensions {
		builder.WriteByte(' ')
		builder.WriteString(key)
		builder.WriteByte(' ')
		builder.WriteString(strings.ToLower(value))
	}
	return builder.String()
}

func cefEventClass(cef *cefEvent) (string, string) {
	lower := cef.searchable()
	severity := "info"
	switch {
	case cef.Severity >= 8:
		severity = "critical"
	case cef.Severity >= 4:
		severity = "warning"
	}
	switch {
	case (containsAny(lower, "radius") && containsAny(lower, "fail", "reject", "denied", "invalid", "timeout", "unreachable")) ||
		(containsAny(lower, "802.1x") && containsAny(lower, "fail", "reject", "denied", "invalid", "timeout")):
		return "auth_failure", "critical"
	case containsAny(lower, "failed password", "authentication failure", "auth failure",
		"login failed", "invalid user", "failed login", "login fail"):
		return "auth_failure", "critical"
	case containsAny(lower, "intrusion", "malware", "exploit", "attack", "threat",
		"botnet", "vulnerability", "ips ", "ids ", "c2 "):
		return "security_threat", higherSeverity(severity, "warning")
	case containsAny(lower, "vpn", "ipsec", "wireguard", "openvpn", "tunnel"):
		return "network_vpn", severity
	case containsAny(lower, "wifi", "wireless", "ssid", "roam", "access point", "adopt", "hostapd"):
		return "network_wifi", severity
	case containsAny(lower, "mc2uc", "sta_cnt["):
		return "network_wifi", "info"
	case containsAny(lower, "wan", "pppoe", "failover"):
		if containsAny(lower, "down", "fail", "disconnect", "lost") {
			return "network_wan", "critical"
		}
		if containsAny(lower, "up", "connect", "restore") {
			return "network_wan", higherSeverity(severity, "warning")
		}
		return "network_wan", severity
	case containsAny(lower, "link", "port", "interface", "stp") &&
		containsAny(lower, "down", "up", "fail", "error"):
		return "network_link", higherSeverity(severity, "warning")
	case containsAny(lower, "firewall", "blocked", "denied", "dropped", "reject"):
		return "network_firewall", severity
	case containsAny(lower, "firmware", "upgrade", "reboot", "config change", "configuration", "restart", "backup"):
		return "system", severity
	}
	return "syslog", severity
}

func higherSeverity(current, minimum string) string {
	rank := map[string]int{"info": 0, "warning": 1, "critical": 2}
	if rank[current] >= rank[minimum] {
		return current
	}
	return minimum
}

func truncateEventField(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
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
