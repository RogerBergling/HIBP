package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
	"github.com/gosnmp/gosnmp"
)

const defaultSNMPInterval = 60 * time.Second

// RunSNMP polls configured network-device hosts. It is a pull path separate
// from the SSH collector and the syslog receiver.
func (s *Server) RunSNMP(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		s.pollSNMPHosts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) handleSNMPPoll(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if host.AuthType != "network" {
		writeError(w, http.StatusBadRequest, "SNMP polling is only available for network devices")
		return
	}
	if s.store.ResolveSetting(host.ID, "snmp.enabled", "0") != "1" {
		writeError(w, http.StatusBadRequest, "SNMP polling is disabled for this host")
		return
	}
	s.pollSNMPHost(r.Context(), host)
	_ = s.store.AddAudit(s.auditActor(r), "snmp-poll", "host", host.ID, "manual poll")
	state, _ := s.store.GetSNMPPollState(host.ID)
	values, _ := s.store.ListSNMPValues(host.ID)
	if values == nil {
		values = []store.SNMPValue{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": state, "values": values})
}

func (s *Server) pollSNMPHosts(ctx context.Context) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		slog.Warn("snmp: list hosts", "error", err)
		return
	}
	semaphore := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, host := range hosts {
		if host.AuthType != "network" {
			continue
		}
		if s.store.ResolveSetting(host.ID, "snmp.enabled", "0") != "1" {
			continue
		}
		interval := durationSetting(s.store.ResolveSetting(host.ID, "snmp.interval", "60s"), defaultSNMPInterval)
		if interval < 10*time.Second {
			interval = 10 * time.Second
		}
		state, err := s.store.GetSNMPPollState(host.ID)
		if err == nil {
			if last, parseErr := time.Parse(time.RFC3339Nano, state.LastPoll); parseErr == nil && time.Since(last) < interval {
				continue
			}
		}
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			}
			s.pollSNMPHost(ctx, host)
		}()
	}
	wg.Wait()
}

func (s *Server) pollSNMPHost(ctx context.Context, host store.Host) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	community := s.store.ResolveSetting(host.ID, "snmp.community", "")
	if community == "" {
		_ = s.store.SetSNMPPollState(host.ID, now, "SNMP community is not configured")
		_ = s.store.SetHostStatus(host.ID, "unknown")
		return
	}
	oidText := s.store.ResolveSetting(host.ID, "snmp.oids", "")
	oids, err := parseOIDList(oidText)
	if err != nil {
		_ = s.store.SetSNMPPollState(host.ID, now, err.Error())
		_ = s.store.SetHostStatus(host.ID, "unknown")
		return
	}
	if len(oids) == 0 {
		_ = s.store.SetSNMPPollState(host.ID, now, "no SNMP OIDs are configured")
		_ = s.store.SetHostStatus(host.ID, "unknown")
		return
	}
	port := host.Port
	if portText := s.store.ResolveSetting(host.ID, "snmp.port", ""); portText != "" {
		port = intSetting(portText, host.Port)
	}
	if port <= 0 || port == 22 {
		port = 161
	}
	if port < 1 || port > 65535 {
		_ = s.store.SetSNMPPollState(host.ID, now, "invalid SNMP port")
		_ = s.store.SetHostStatus(host.ID, "unknown")
		return
	}
	version := gosnmp.Version2c
	if s.store.ResolveSetting(host.ID, "snmp.version", "2c") == "1" {
		version = gosnmp.Version1
	}
	params := &gosnmp.GoSNMP{
		Target:    host.Address,
		Port:      uint16(port),
		Community: community,
		Version:   version,
		Timeout:   5 * time.Second,
		Retries:   1,
		MaxOids:   20,
	}
	if err := params.Connect(); err != nil {
		_ = s.store.SetSNMPPollState(host.ID, now, fmt.Sprintf("%s:%d: %s", host.Address, port, boundError(err)))
		_ = s.store.SetHostStatus(host.ID, "unreachable")
		slog.Warn("snmp: connect", "host", host.Name, "target", host.Address, "port", port, "error", err)
		return
	}
	defer params.Conn.Close()
	packet, err := params.Get(oids)
	if err != nil {
		_ = s.store.SetSNMPPollState(host.ID, now, fmt.Sprintf("%s:%d: %s", host.Address, port, boundError(err)))
		_ = s.store.SetHostStatus(host.ID, "unreachable")
		slog.Warn("snmp: get", "host", host.Name, "target", host.Address, "port", port, "error", err)
		return
	}
	values := make([]store.SNMPValue, 0, len(packet.Variables))
	for _, pdu := range packet.Variables {
		oid := normalizeOID(pdu.Name)
		if oid == "" {
			continue
		}
		value, valueType := snmpPDUValue(pdu)
		values = append(values, store.SNMPValue{
			HostID: host.ID, OID: oid, Value: value, ValueType: valueType, CollectedAt: now,
		})
	}
	if err := s.store.SaveSNMPValues(host.ID, now, values); err != nil {
		_ = s.store.SetSNMPPollState(host.ID, now, boundError(err))
		_ = s.store.SetHostStatus(host.ID, "unknown")
		slog.Warn("snmp: save values", "host", host.Name, "error", err)
		return
	}
	if err := s.store.SetSNMPPollState(host.ID, now, ""); err != nil {
		slog.Warn("snmp: save poll state", "host", host.Name, "error", err)
	}
	_ = s.store.SetHostStatus(host.ID, "reachable")
}

func normalizeOID(oid string) string {
	return strings.TrimPrefix(strings.TrimSpace(oid), ".")
}

func snmpPDUValue(pdu gosnmp.SnmpPDU) (string, string) {
	switch value := pdu.Value.(type) {
	case int:
		return strconv.Itoa(value), "number"
	case int32:
		return strconv.FormatInt(int64(value), 10), "number"
	case int64:
		return strconv.FormatInt(value, 10), "number"
	case uint:
		return strconv.FormatUint(uint64(value), 10), "number"
	case uint32:
		return strconv.FormatUint(uint64(value), 10), "number"
	case uint64:
		return strconv.FormatUint(value, 10), "number"
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), "number"
	case string:
		if len(value) > 512 {
			value = value[:512]
		}
		return value, "string"
	case []byte:
		text := string(value)
		if len(text) > 512 {
			text = text[:512]
		}
		return text, "string"
	case nil:
		return "", "string"
	default:
		text := fmt.Sprint(value)
		if len(text) > 512 {
			text = text[:512]
		}
		return text, "string"
	}
}

func boundError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}
