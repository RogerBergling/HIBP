package server

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/RogerBergling/hibp/internal/store"
)

type importRequest struct {
	CSV             string `json:"csv"`
	Commit          bool   `json:"commit"`
	DuplicatePolicy string `json:"duplicate_policy"`
	DefaultKeyPath  string `json:"default_key_path"`
}

type importRow struct {
	Row       int    `json:"row"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"`
	KeyPath   string `json:"key_path"`
	GroupName string `json:"group_name"`
	Tags      string `json:"tags"`
	CMDBCIID  string `json:"cmdb_ci_id"`
	Error     string `json:"error,omitempty"`
}

type importResult struct {
	Rows     []importRow `json:"rows"`
	Imported int         `json:"imported"`
	Updated  int         `json:"updated"`
	Skipped  int         `json:"skipped"`
	Errors   []string    `json:"errors"`
}

func (s *Server) importCSV(ctx context.Context, request importRequest) (importResult, error) {
	if len(request.CSV) > 10<<20 {
		return importResult{}, errors.New("CSV is larger than 10 MiB")
	}
	if strings.TrimSpace(request.CSV) == "" {
		return importResult{}, errors.New("CSV is empty")
	}
	policy := request.DuplicatePolicy
	if policy == "" {
		policy = "error"
	}
	switch policy {
	case "error", "skip", "update":
	default:
		return importResult{}, errors.New("duplicate_policy must be error, skip, or update")
	}
	if !looksLikeCSV(request.CSV) {
		converted, err := txtToCSV(request.CSV, request.DefaultKeyPath)
		if err != nil {
			return importResult{}, err
		}
		request.CSV = converted
	}

	reader := csv.NewReader(strings.NewReader(request.CSV))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return importResult{}, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) == 0 {
		return importResult{}, errors.New("CSV has no header")
	}
	if len(records) > 5001 {
		return importResult{}, errors.New("CSV has more than 5,000 data rows")
	}

	header := make(map[string]int)
	for index, cell := range records[0] {
		header[strings.ToLower(strings.TrimSpace(cell))] = index
	}
	if _, ok := header["name"]; !ok {
		return importResult{}, errors.New("CSV header must contain name")
	}
	if _, ok := header["address"]; !ok {
		return importResult{}, errors.New("CSV header must contain address")
	}

	result := importResult{Rows: []importRow{}, Errors: []string{}}
	for index, record := range records[1:] {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		rowNumber := index + 2
		row := importRow{
			Row:       rowNumber,
			Name:      field(record, header, "name"),
			Address:   field(record, header, "address"),
			Username:  field(record, header, "username"),
			AuthType:  field(record, header, "auth_type"),
			KeyPath:   field(record, header, "key_path"),
			GroupName: field(record, header, "group"),
			Tags:      field(record, header, "tags"),
			CMDBCIID:  field(record, header, "cmdb_ci_id"),
		}
		port := 22
		if raw := field(record, header, "port"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				row.Error = "port is not a number"
				result.Rows = append(result.Rows, row)
				result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
				continue
			}
			port = parsed
		}
		row.Port = port
		if row.AuthType == "" {
			row.AuthType = "key"
		}
		if row.KeyPath == "" {
			row.KeyPath = strings.TrimSpace(request.DefaultKeyPath)
		}
		host := store.Host{
			Name: row.Name, Address: row.Address, Port: row.Port, Username: row.Username,
			AuthType: row.AuthType, KeyPath: row.KeyPath, GroupName: row.GroupName,
			Tags: row.Tags, CMDBCIID: row.CMDBCIID,
		}
		if err := store.ValidateHost(host); err != nil {
			row.Error = err.Error()
			result.Rows = append(result.Rows, row)
			result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
			continue
		}
		if row.KeyPath != "" {
			if !filepath.IsAbs(row.KeyPath) {
				row.Error = "key_path must be absolute"
				result.Rows = append(result.Rows, row)
				result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
				continue
			}
		}

		if request.Commit {
			existing, err := s.store.FindHostByAddress(row.Address, row.Port)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				row.Error = err.Error()
				result.Rows = append(result.Rows, row)
				result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
				continue
			}
			if err == nil {
				switch policy {
				case "skip":
					result.Skipped++
					row.Error = "skipped: host already exists"
					result.Rows = append(result.Rows, row)
					continue
				case "error":
					row.Error = "host already exists"
					result.Rows = append(result.Rows, row)
					result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
					continue
				case "update":
					host.ID = existing.ID
					host.CreatedAt = existing.CreatedAt
					if _, err := s.store.UpdateHost(host); err != nil {
						row.Error = err.Error()
						result.Rows = append(result.Rows, row)
						result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
						continue
					}
					result.Updated++
					result.Rows = append(result.Rows, row)
					continue
				}
			}
			if _, err := s.store.CreateHost(host); err != nil {
				row.Error = err.Error()
				result.Rows = append(result.Rows, row)
				result.Errors = append(result.Errors, fmt.Sprintf("row %d: %s", rowNumber, row.Error))
				continue
			}
			result.Imported++
		}
		result.Rows = append(result.Rows, row)
	}
	return result, nil
}

func field(record []string, header map[string]int, name string) string {
	index, ok := header[name]
	if !ok || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func looksLikeCSV(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.Contains(line, ",")
	}
	return false
}

func txtToCSV(text, defaultKeyPath string) (string, error) {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{"name", "address", "port", "username", "auth_type", "key_path"}); err != nil {
		return "", err
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		row, err := parseTXTLine(line, defaultKeyPath)
		if err != nil {
			return "", err
		}
		if err := writer.Write([]string{row.Name, row.Address, strconv.Itoa(row.Port), row.Username, row.AuthType, row.KeyPath}); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func parseTXTLine(line, defaultKeyPath string) (importRow, error) {
	user := "root"
	target := line
	if at := strings.Index(line, "@"); at >= 0 {
		user = strings.TrimSpace(line[:at])
		target = strings.TrimSpace(line[at+1:])
	}
	if user == "" || target == "" {
		return importRow{}, fmt.Errorf("invalid host line %q", line)
	}
	host := target
	port := 22
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]")
		if end < 0 {
			return importRow{}, fmt.Errorf("invalid IPv6 host %q", line)
		}
		host = target[1:end]
		rest := target[end+1:]
		if strings.HasPrefix(rest, ":") {
			parsed, err := strconv.Atoi(strings.TrimPrefix(rest, ":"))
			if err != nil {
				return importRow{}, fmt.Errorf("invalid port in %q", line)
			}
			port = parsed
		}
	} else if strings.Count(target, ":") == 1 {
		parts := strings.SplitN(target, ":", 2)
		if parsed, err := strconv.Atoi(parts[1]); err == nil {
			host = parts[0]
			port = parsed
		}
	}
	if port < 1 || port > 65535 {
		return importRow{}, fmt.Errorf("invalid port in %q", line)
	}
	return importRow{
		Name: host, Address: host, Port: port, Username: user,
		AuthType: "key", KeyPath: strings.TrimSpace(defaultKeyPath),
	}, nil
}
