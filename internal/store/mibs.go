package store

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
)

// MIBEnum maps a numeric SNMP enumeration value to its MIB label.
type MIBEnum struct {
	Value int64  `json:"value"`
	Label string `json:"label"`
}

// MIBFile is an uploaded MIB source file. Content is never returned by the
// list API; use ListMIBFilesWithContent only for a rebuild.
type MIBFile struct {
	ID          int64    `json:"id"`
	Filename    string   `json:"filename"`
	Modules     []string `json:"modules"`
	SymbolCount int      `json:"symbol_count"`
	SizeBytes   int      `json:"size_bytes"`
	ImportedAt  string   `json:"imported_at"`
	Content     string   `json:"-"`
}

// MIBSymbol is one resolved name/OID mapping. Kind is scalar, column, table,
// row, node, notification, and so on.
type MIBSymbol struct {
	OID         string    `json:"oid"`
	Name        string    `json:"name"`
	Module      string    `json:"module"`
	Kind        string    `json:"kind"`
	Syntax      string    `json:"syntax,omitempty"`
	Units       string    `json:"units,omitempty"`
	Enums       []MIBEnum `json:"enums,omitempty"`
	Description string    `json:"description,omitempty"`
}

// MIBSummary describes the imported MIB library without loading file content.
type MIBSummary struct {
	Files       []MIBFile `json:"files"`
	SymbolCount int       `json:"symbol_count"`
	Modules     []string  `json:"modules"`
}

func (s *Store) ListMIBFiles() ([]MIBFile, error) {
	return s.listMIBFiles(false)
}

func (s *Store) ListMIBFilesWithContent() ([]MIBFile, error) {
	return s.listMIBFiles(true)
}

func (s *Store) listMIBFiles(withContent bool) ([]MIBFile, error) {
	contentColumn := "''"
	if withContent {
		contentColumn = "content"
	}
	rows, err := s.db.Query(`SELECT id,filename,modules,symbol_count,size_bytes,imported_at,` +
		contentColumn + ` FROM snmp_mibs ORDER BY filename`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	files := make([]MIBFile, 0)
	for rows.Next() {
		var file MIBFile
		var modules string
		if err := rows.Scan(&file.ID, &file.Filename, &modules, &file.SymbolCount,
			&file.SizeBytes, &file.ImportedAt, &file.Content); err != nil {
			return nil, err
		}
		file.Modules = splitMIBModules(modules)
		files = append(files, file)
	}
	return files, rows.Err()
}

// ReplaceMIBState atomically replaces the stored MIB files and symbol index.
// The server parses and resolves the complete library before calling this.
func (s *Store) ReplaceMIBState(files []MIBFile, symbols []MIBSymbol) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM snmp_mib_symbols"); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec("DELETE FROM snmp_mibs"); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, file := range files {
		importedAt := strings.TrimSpace(file.ImportedAt)
		if importedAt == "" {
			importedAt = crypto.Now()
		}
		if _, err := tx.Exec(`INSERT INTO snmp_mibs
			(filename,content,modules,symbol_count,size_bytes,imported_at)
			VALUES(?,?,?,?,?,?)`,
			file.Filename, file.Content, joinMIBModules(file.Modules), file.SymbolCount,
			file.SizeBytes, importedAt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	for _, symbol := range symbols {
		enums := ""
		if len(symbol.Enums) > 0 {
			encoded, err := json.Marshal(symbol.Enums)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			enums = string(encoded)
		}
		if _, err := tx.Exec(`INSERT INTO snmp_mib_symbols
			(oid,name,module,kind,syntax,units,enums,description)
			VALUES(?,?,?,?,?,?,?,?)`,
			symbol.OID, symbol.Name, symbol.Module, symbol.Kind, symbol.Syntax,
			symbol.Units, enums, symbol.Description); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) MIBSummary() (MIBSummary, error) {
	files, err := s.ListMIBFiles()
	if err != nil {
		return MIBSummary{}, err
	}
	summary := MIBSummary{Files: files, Modules: make([]string, 0)}
	seen := make(map[string]bool)
	for _, file := range files {
		for _, module := range file.Modules {
			if module == "" || seen[module] {
				continue
			}
			seen[module] = true
			summary.Modules = append(summary.Modules, module)
		}
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM snmp_mib_symbols").Scan(&summary.SymbolCount); err != nil {
		return summary, err
	}
	sort.Strings(summary.Modules)
	return summary, nil
}

// ListMIBSymbols searches names, OIDs, and modules. An empty query lists the
// alphabetically first symbols.
func (s *Store) ListMIBSymbols(query string, limit int) ([]MIBSymbol, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query = strings.TrimSpace(query)
	var rows rowsScanner
	var err error
	if query == "" {
		rows, err = s.db.Query(`SELECT oid,name,module,kind,syntax,units,enums,description
			FROM snmp_mib_symbols ORDER BY name LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(`SELECT oid,name,module,kind,syntax,units,enums,description
			FROM snmp_mib_symbols
			WHERE instr(lower(name), lower(?)) > 0
			   OR instr(oid, ?) > 0
			   OR instr(lower(module), lower(?)) > 0
			ORDER BY name LIMIT ?`, query, query, query, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	symbols := make([]MIBSymbol, 0)
	for rows.Next() {
		symbol, err := scanMIBSymbol(rows)
		if err != nil {
			return nil, err
		}
		symbols = append(symbols, symbol)
	}
	return symbols, rows.Err()
}

// LookupMIBSymbolByName resolves a plain or module-qualified symbol name.
func (s *Store) LookupMIBSymbolByName(name, module string) (MIBSymbol, error) {
	name = strings.TrimSpace(name)
	module = strings.TrimSpace(module)
	query := `SELECT oid,name,module,kind,syntax,units,enums,description
		FROM snmp_mib_symbols WHERE lower(name)=lower(?)`
	args := []any{name}
	if module != "" {
		query += " AND lower(module)=lower(?)"
		args = append(args, module)
	}
	query += ` ORDER BY CASE kind WHEN 'scalar' THEN 0 WHEN 'column' THEN 1 ELSE 2 END,
		length(oid), module LIMIT 1`
	return scanMIBSymbol(s.db.QueryRow(query, args...))
}

// LookupMIBSymbolByOID finds the longest matching symbol for an OID so an
// indexed instance such as sysUpTime.0 maps back to sysUpTime.
func (s *Store) LookupMIBSymbolByOID(oid string) (MIBSymbol, error) {
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	return scanMIBSymbol(s.db.QueryRow(`SELECT oid,name,module,kind,syntax,units,enums,description
		FROM snmp_mib_symbols
		WHERE ? = oid OR ? LIKE oid || '.%'
		ORDER BY length(oid) DESC,
			CASE kind WHEN 'scalar' THEN 0 WHEN 'column' THEN 1 ELSE 2 END,
			name LIMIT 1`, oid, oid))
}

type rowScanner interface {
	Scan(dest ...any) error
}

type rowsScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

func scanMIBSymbol(scanner rowScanner) (MIBSymbol, error) {
	var symbol MIBSymbol
	var enums string
	if err := scanner.Scan(&symbol.OID, &symbol.Name, &symbol.Module, &symbol.Kind,
		&symbol.Syntax, &symbol.Units, &enums, &symbol.Description); err != nil {
		return symbol, err
	}
	if enums != "" {
		_ = json.Unmarshal([]byte(enums), &symbol.Enums)
	}
	return symbol, nil
}

func splitMIBModules(value string) []string {
	parts := strings.Split(value, ",")
	modules := make([]string, 0, len(parts))
	for _, module := range parts {
		module = strings.TrimSpace(module)
		if module != "" {
			modules = append(modules, module)
		}
	}
	return modules
}

func joinMIBModules(modules []string) string {
	return strings.Join(modules, ", ")
}
