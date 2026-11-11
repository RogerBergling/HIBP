package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/RogerBergling/hibp/internal/store"
)

type cmdbImportRequest struct {
	Data            string `json:"data"`
	Format          string `json:"format"`
	Mode            string `json:"mode"`
	Commit          bool   `json:"commit"`
	DefaultKeyPath  string `json:"default_key_path"`
	DefaultUsername string `json:"default_username"`
}

type cmdbImportRow struct {
	Row         int    `json:"row"`
	Action      string `json:"action"`
	MatchedBy   string `json:"matched_by,omitempty"`
	HostID      string `json:"host_id,omitempty"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthType    string `json:"auth_type"`
	KeyPath     string `json:"key_path,omitempty"`
	GroupName   string `json:"group_name,omitempty"`
	Tags        string `json:"tags,omitempty"`
	CMDBCIID    string `json:"cmdb_ci_id,omitempty"`
	OSFamily    string `json:"os_family,omitempty"`
	OSVersion   string `json:"os_version,omitempty"`
	Error       string `json:"error,omitempty"`
	prepared    store.Host
	hasPrepared bool
}

type cmdbImportResult struct {
	Format   string          `json:"format"`
	Mode     string          `json:"mode"`
	Rows     []cmdbImportRow `json:"rows"`
	Created  int             `json:"created"`
	Updated  int             `json:"updated"`
	Skipped  int             `json:"skipped"`
	Problems []string        `json:"problems"`
}

type cmdbRecord struct {
	row     int
	values  map[string]string
	present map[string]bool
}

func normalizeCMDBKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer(" ", "_", "-", "_", "/", "_").Replace(value)
}

func cmdbValue(values map[string]string, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := values[normalizeCMDBKey(key)]; ok {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func parseCMDBRecords(format, data string) ([]cmdbRecord, string, error) {
	if len(data) > 10<<20 {
		return nil, format, errors.New("CMDB import is larger than 10 MiB")
	}
	data = strings.TrimSpace(data)
	data = strings.TrimPrefix(data, "\ufeff")
	if data == "" {
		return nil, format, errors.New("CMDB import is empty")
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		if strings.HasPrefix(data, "{") || strings.HasPrefix(data, "[") {
			format = "json"
		} else {
			format = "csv"
		}
	}
	switch format {
	case "csv":
		records, err := parseCMDBRecordsCSV(data)
		return records, format, err
	case "json":
		records, err := parseCMDBRecordsJSON(data)
		return records, format, err
	default:
		return nil, format, errors.New("format must be auto, csv, or json")
	}
}

func parseCMDBRecordsCSV(data string) ([]cmdbRecord, error) {
	reader := csv.NewReader(strings.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) == 0 {
		return nil, errors.New("CSV has no header")
	}
	if len(records) > 5001 {
		return nil, errors.New("CSV has more than 5,000 data rows")
	}
	header := make([]string, len(records[0]))
	for index, cell := range records[0] {
		header[index] = normalizeCMDBKey(cell)
	}
	result := make([]cmdbRecord, 0, len(records)-1)
	for index, record := range records[1:] {
		values := make(map[string]string, len(header))
		present := make(map[string]bool, len(header))
		for column, key := range header {
			if key == "" {
				continue
			}
			value := ""
			if column < len(record) {
				value = strings.TrimSpace(record[column])
			}
			values[key] = value
			present[key] = true
		}
		result = append(result, cmdbRecord{row: index + 2, values: values, present: present})
	}
	if len(result) == 0 {
		return nil, errors.New("CSV has no data rows")
	}
	return result, nil
}

func parseCMDBRecordsJSON(data string) ([]cmdbRecord, error) {
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	entries, err := cmdbJSONEntries(value)
	if err != nil {
		return nil, err
	}
	if len(entries) > 5000 {
		return nil, errors.New("JSON has more than 5,000 records")
	}
	result := make([]cmdbRecord, 0, len(entries))
	for index, entry := range entries {
		values := make(map[string]string)
		present := make(map[string]bool)
		flattenCMDBJSON(values, present, "", entry)
		result = append(result, cmdbRecord{row: index + 1, values: values, present: present})
	}
	if len(result) == 0 {
		return nil, errors.New("JSON has no records")
	}
	return result, nil
}

func cmdbJSONEntries(value any) ([]map[string]any, error) {
	switch typed := value.(type) {
	case []any:
		entries := make([]map[string]any, 0, len(typed))
		for index, entry := range typed {
			object, ok := entry.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("JSON record %d is not an object", index+1)
			}
			entries = append(entries, object)
		}
		return entries, nil
	case map[string]any:
		for _, key := range []string{"hosts", "cis", "items", "records", "data"} {
			if nested, ok := typed[key]; ok {
				if entries, err := cmdbJSONEntries(nested); err == nil {
					return entries, nil
				}
			}
		}
		return []map[string]any{typed}, nil
	default:
		return nil, errors.New("JSON must be an object or an array of objects")
	}
}

func flattenCMDBJSON(values map[string]string, present map[string]bool, prefix string, object map[string]any) {
	for key, value := range object {
		normalized := normalizeCMDBKey(key)
		full := normalized
		if prefix != "" {
			full = normalizeCMDBKey(prefix + "." + key)
		}
		switch typed := value.(type) {
		case map[string]any:
			flattenCMDBJSON(values, present, full, typed)
		case []any:
			parts := make([]string, 0, len(typed))
			for _, entry := range typed {
				parts = append(parts, cmdbJSONScalar(entry))
			}
			joined := strings.Join(parts, ",")
			values[full] = joined
			present[full] = true
			if prefix == "" || cmdbMetadataPrefix(prefix) {
				values[normalized] = joined
				present[normalized] = true
			}
		default:
			scalar := cmdbJSONScalar(value)
			values[full] = scalar
			present[full] = true
			if prefix == "" || cmdbMetadataPrefix(prefix) {
				values[normalized] = scalar
				present[normalized] = true
			}
		}
	}
}

func cmdbMetadataPrefix(prefix string) bool {
	switch normalizeCMDBKey(prefix) {
	case "attributes", "custom", "fields", "properties", "metadata":
		return true
	default:
		return false
	}
}

func cmdbJSONScalar(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

func cmdbAddressKey(address string, port int) string {
	return strings.ToLower(strings.TrimSpace(address)) + ":" + strconv.Itoa(port)
}

func (s *Server) prepareCMDBImport(ctx context.Context, request cmdbImportRequest) (cmdbImportResult, error) {
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "overwrite" {
		return cmdbImportResult{}, errors.New("mode must be merge or overwrite")
	}
	records, format, err := parseCMDBRecords(request.Format, request.Data)
	if err != nil {
		return cmdbImportResult{}, err
	}
	hosts, err := s.store.ListHosts()
	if err != nil {
		return cmdbImportResult{}, err
	}
	byCMDB := make(map[string]store.Host)
	byAddress := make(map[string]store.Host)
	for _, host := range hosts {
		if strings.TrimSpace(host.CMDBCIID) != "" {
			byCMDB[host.CMDBCIID] = host
		}
		byAddress[cmdbAddressKey(host.Address, host.Port)] = host
	}
	defaults := store.Host{
		Username: strings.TrimSpace(request.DefaultUsername),
		KeyPath:  strings.TrimSpace(request.DefaultKeyPath),
	}
	usedHosts := make(map[string]bool)
	usedAddresses := make(map[string]int)
	result := cmdbImportResult{Format: format, Mode: mode, Rows: []cmdbImportRow{}, Problems: []string{}}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		row, base, matchedBy, err := prepareCMDBRow(record, defaults, mode, byCMDB, byAddress)
		if err != nil {
			row.Action = "error"
			row.Error = err.Error()
			result.Problems = append(result.Problems, fmt.Sprintf("row %d: %s", row.Row, row.Error))
			result.Rows = append(result.Rows, row)
			continue
		}
		if base.ID != "" {
			if usedHosts[base.ID] {
				row.Action = "error"
				row.Error = "another row in this import targets the same host"
				result.Problems = append(result.Problems, fmt.Sprintf("row %d: %s", row.Row, row.Error))
				result.Rows = append(result.Rows, row)
				continue
			}
			usedHosts[base.ID] = true
			row.Action = "update"
			row.HostID = base.ID
			row.MatchedBy = matchedBy
			result.Updated++
		} else {
			key := cmdbAddressKey(row.Address, row.Port)
			if previous, ok := usedAddresses[key]; ok {
				row.Action = "error"
				row.Error = fmt.Sprintf("address and port already used by row %d", previous)
				result.Problems = append(result.Problems, fmt.Sprintf("row %d: %s", row.Row, row.Error))
				result.Rows = append(result.Rows, row)
				continue
			}
			usedAddresses[key] = row.Row
			row.Action = "create"
			result.Created++
		}
		result.Rows = append(result.Rows, row)
	}
	return result, nil
}

func prepareCMDBRow(record cmdbRecord, defaults store.Host, mode string, byCMDB, byAddress map[string]store.Host) (cmdbImportRow, store.Host, string, error) {
	row := cmdbImportRow{Row: record.row}
	name, _ := cmdbValue(record.values, "name", "ci_name", "hostname", "host_name", "alias")
	address, addressPresent := cmdbValue(record.values, "address", "ip_address", "ipaddress", "management_ip", "hostname", "host")
	if address == "" && addressPresent {
		address = name
	}
	if address == "" && cmdbAddressLike(name) {
		address = name
	}
	if address == "" {
		row.Name = name
		return row, store.Host{}, "", errors.New("address is required")
	}
	if name == "" {
		name = address
	}
	row.Name = name
	row.Address = address
	port := 22
	portPresent := false
	if raw, ok := cmdbValue(record.values, "port", "ssh_port"); ok && raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			return row, store.Host{}, "", errors.New("port must be between 1 and 65535")
		}
		port = parsed
		portPresent = true
	}
	row.Port = port
	cmdbID, _ := cmdbValue(record.values, "cmdb_ci_id", "ci_id", "external_id")

	var base store.Host
	matchedBy := ""
	if cmdbID != "" {
		if host, ok := byCMDB[cmdbID]; ok {
			base = host
			matchedBy = "cmdb_ci_id"
		}
	}
	if base.ID == "" {
		if host, ok := byAddress[cmdbAddressKey(address, port)]; ok {
			base = host
			matchedBy = "address_port"
		}
	}

	host := base
	if host.ID == "" {
		host = store.Host{}
	}
	host.Name = name
	host.Address = address
	if portPresent || host.Port == 0 {
		host.Port = port
	}
	if value, present := cmdbValue(record.values, "username", "ssh_username", "user", "ssh_user"); present && value != "" {
		host.Username = value
	} else if host.Username == "" {
		host.Username = defaults.Username
	}
	if value, present := cmdbValue(record.values, "auth_type", "ssh_auth_type"); present && value != "" {
		host.AuthType = value
	}
	if value, present := cmdbValue(record.values, "key_path", "ssh_key_path"); present && value != "" {
		host.KeyPath = value
	} else if host.KeyPath == "" {
		host.KeyPath = defaults.KeyPath
	}
	if host.AuthType == "" {
		if host.KeyPath != "" {
			host.AuthType = "key"
		} else {
			host.AuthType = "agent"
		}
	}
	applyOptional := func(value string, present bool, target *string) {
		if present && (mode == "overwrite" || value != "") {
			*target = value
		}
	}
	group, groupPresent := cmdbValue(record.values, "group", "group_name", "environment", "env")
	applyOptional(group, groupPresent, &host.GroupName)
	tags, tagsPresent := cmdbValue(record.values, "tags")
	applyOptional(tags, tagsPresent, &host.Tags)
	osFamily, familyPresent := cmdbValue(record.values, "os_family")
	applyOptional(osFamily, familyPresent, &host.OSFamily)
	osVersion, versionPresent := cmdbValue(record.values, "os_version", "custom.os_version", "custom.os")
	applyOptional(osVersion, versionPresent, &host.OSVersion)
	if cmdbID != "" {
		host.CMDBCIID = cmdbID
	}
	row.Name = host.Name
	row.Address = host.Address
	row.Port = host.Port
	row.Username = host.Username
	row.AuthType = host.AuthType
	row.KeyPath = host.KeyPath
	row.GroupName = host.GroupName
	row.Tags = host.Tags
	row.CMDBCIID = host.CMDBCIID
	row.OSFamily = host.OSFamily
	row.OSVersion = host.OSVersion
	if err := store.ValidateHost(host); err != nil {
		return row, base, matchedBy, err
	}
	row.prepared = host
	row.hasPrepared = true
	return row, base, matchedBy, nil
}

func cmdbAddressLike(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " /:@") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	return strings.Contains(value, ".") && !strings.HasPrefix(value, ".") && !strings.HasSuffix(value, ".")
}

func (s *Server) handleCMDBImport(w http.ResponseWriter, r *http.Request) {
	var request cmdbImportRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	result, err := s.prepareCMDBImport(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Commit {
		created := 0
		updated := 0
		skipped := 0
		for index := range result.Rows {
			row := &result.Rows[index]
			if row.Action == "error" {
				skipped++
				continue
			}
			if !row.hasPrepared {
				row.Action = "error"
				row.Error = "internal import row was not prepared"
				result.Problems = append(result.Problems, fmt.Sprintf("row %d: %s", row.Row, row.Error))
				skipped++
				continue
			}
			if row.Action == "create" {
				host, err := s.store.CreateHost(row.prepared)
				if err != nil {
					row.Action = "error"
					row.Error = err.Error()
					result.Problems = append(result.Problems, fmt.Sprintf("row %d: %s", row.Row, err))
					skipped++
					continue
				}
				row.HostID = host.ID
				created++
				continue
			}
			host, err := s.store.UpdateHost(row.prepared)
			if err != nil {
				row.Action = "error"
				row.Error = err.Error()
				result.Problems = append(result.Problems, fmt.Sprintf("row %d: %s", row.Row, err))
				skipped++
				continue
			}
			row.HostID = host.ID
			updated++
		}
		result.Created = created
		result.Updated = updated
		result.Skipped = skipped
		_ = s.store.AddAudit(s.auditActor(r), "cmdb-import", "hosts", "",
			fmt.Sprintf("mode=%s format=%s created=%d updated=%d skipped=%d", result.Mode, result.Format, created, updated, skipped))
	}
	writeJSON(w, http.StatusOK, result)
}
