package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing/fstest"
	"time"
	"unicode/utf8"

	"github.com/RogerBergling/hibp/internal/store"
	"github.com/golangsnmp/gomib"
	"github.com/golangsnmp/gomib/mib"
)

const (
	maxMIBFileBytes    = 2 << 20
	maxMIBLibraryBytes = 25 << 20
	maxMIBUploadBytes  = maxMIBLibraryBytes + (2 << 20)
	maxMIBUploadFiles  = 50
	maxMIBSymbols      = 50000
	maxMIBDiagnostics  = 25
)

var mibInstanceSuffixPattern = regexp.MustCompile(`^(\.[0-9]+)+$`)
var mibFilenamePattern = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type mibDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code,omitempty"`
	Module   string `json:"module,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
}

type mibParseResult struct {
	Symbols     []store.MIBSymbol
	Modules     []string
	Diagnostics []mibDiagnostic
}

type mibImportFile struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

type mibImportRequest struct {
	Files []mibImportFile `json:"files"`
}

// parseMIBFiles parses and resolves the complete imported MIB library. The
// returned symbols are bounded and sorted for stable storage and lookup.
func parseMIBFiles(ctx context.Context, files []store.MIBFile) (mibParseResult, error) {
	result := mibParseResult{
		Symbols:     make([]store.MIBSymbol, 0),
		Modules:     make([]string, 0),
		Diagnostics: make([]mibDiagnostic, 0),
	}
	if len(files) == 0 {
		return result, nil
	}
	sourceFS := fstest.MapFS{}
	for index, file := range files {
		name := fmt.Sprintf("%03d-%s", index, sanitizeMIBFilename(file.Filename))
		name = strings.TrimSuffix(name, filepath.Ext(name)) + ".mib"
		sourceFS[name] = &fstest.MapFile{Data: []byte(file.Content)}
	}
	source := gomib.FS("hibp-mibs", sourceFS)
	model, err := gomib.Load(ctx,
		gomib.WithSource(source),
		gomib.WithResolverStrictness(mib.ResolverPermissive),
		gomib.WithDiagnosticConfig(mib.DiagnosticConfig{
			Reporting: mib.ReportingDefault,
			FailAt:    mib.SeverityFatal,
			Overrides: map[string]mib.Severity{
				"import-not-found": mib.SeverityWarning,
			},
		}),
	)
	if err != nil {
		if model != nil {
			result.Diagnostics = collectMIBDiagnostics(model)
			if len(result.Diagnostics) > 0 {
				return result, fmt.Errorf("parse MIB files: %s", result.Diagnostics[0].Message)
			}
		}
		return result, fmt.Errorf("parse MIB files: %w", err)
	}
	if model == nil {
		return result, errors.New("parse MIB files: no MIB model was returned")
	}
	moduleNames := make(map[string]bool)
	for _, module := range model.Modules() {
		if module == nil || module.IsBase() || strings.TrimSpace(module.Name()) == "" {
			continue
		}
		moduleNames[module.Name()] = true
	}
	result.Modules = make([]string, 0, len(moduleNames))
	for name := range moduleNames {
		result.Modules = append(result.Modules, name)
	}
	sort.Strings(result.Modules)

	seen := make(map[string]bool)
	for symbol := range model.AllSymbols() {
		module := symbol.Module()
		if module == nil || module.IsBase() {
			continue
		}
		node := symbol.Node()
		if node == nil {
			continue
		}
		name := strings.TrimSpace(symbol.Name())
		oid := strings.TrimSpace(node.OID().String())
		if name == "" || oid == "" {
			continue
		}
		key := strings.ToLower(module.Name() + "\x00" + name)
		if seen[key] {
			continue
		}
		seen[key] = true
		kind := symbol.Kind().String()
		syntax := ""
		units := ""
		enums := make([]store.MIBEnum, 0)
		if object := symbol.Object(); object != nil {
			kind = object.Kind().String()
			if object.Type() != nil {
				syntax = object.Type().Name()
			}
			units = boundMIBText(object.Units(), 64)
			for _, value := range object.EffectiveEnums() {
				if len(enums) >= 64 {
					break
				}
				enums = append(enums, store.MIBEnum{Value: value.Value, Label: boundMIBText(value.Label, 128)})
			}
		}
		result.Symbols = append(result.Symbols, store.MIBSymbol{
			OID:         boundMIBText(oid, 256),
			Name:        boundMIBText(name, 128),
			Module:      boundMIBText(module.Name(), 128),
			Kind:        boundMIBText(kind, 32),
			Syntax:      boundMIBText(syntax, 128),
			Units:       units,
			Enums:       enums,
			Description: boundMIBText(strings.TrimSpace(symbol.Description()), 2048),
		})
	}
	if len(result.Symbols) == 0 {
		result.Diagnostics = collectMIBDiagnostics(model)
		message := "no SNMP MIB symbols were resolved"
		if len(result.Diagnostics) > 0 {
			message += ": " + result.Diagnostics[0].Message
		}
		return result, errors.New(message)
	}
	if len(result.Symbols) > maxMIBSymbols {
		return result, fmt.Errorf("MIB library has more than %d symbols; import fewer modules", maxMIBSymbols)
	}
	sort.Slice(result.Symbols, func(i, j int) bool {
		if result.Symbols[i].OID == result.Symbols[j].OID {
			return result.Symbols[i].Name < result.Symbols[j].Name
		}
		return result.Symbols[i].OID < result.Symbols[j].OID
	})
	result.Diagnostics = collectMIBDiagnostics(model)
	return result, nil
}

func collectMIBDiagnostics(model *mib.Mib) []mibDiagnostic {
	diagnostics := make([]mibDiagnostic, 0, maxMIBDiagnostics)
	seen := make(map[string]bool)
	add := func(diagnostic mibDiagnostic) {
		if len(diagnostics) >= maxMIBDiagnostics {
			return
		}
		key := diagnostic.Code + "\x00" + diagnostic.Module + "\x00" + diagnostic.Message
		if seen[key] {
			return
		}
		seen[key] = true
		diagnostics = append(diagnostics, diagnostic)
	}
	for _, diagnostic := range model.Diagnostics() {
		add(mibDiagnostic{
			Severity: diagnostic.Severity.String(),
			Code:     diagnostic.Code,
			Module:   diagnostic.Module,
			Line:     diagnostic.Line,
			Message:  boundMIBText(strings.TrimSpace(diagnostic.Message), 512),
		})
	}
	for _, ref := range model.Unresolved() {
		add(mibDiagnostic{
			Severity: "warning",
			Code:     "unresolved-" + ref.Kind.String(),
			Module:   ref.Module,
			Message:  boundMIBText(strings.TrimSpace(ref.Symbol+": "+ref.Reason), 512),
		})
	}
	return diagnostics
}

func boundMIBText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func sanitizeMIBFilename(value string) string {
	value = filepath.Base(strings.TrimSpace(value))
	value = mibFilenamePattern.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._-")
	if value == "" {
		value = "mib"
	}
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}

func validateMIBUpload(filename, content string) (string, error) {
	filename = sanitizeMIBFilename(filename)
	if content == "" {
		return filename, fmt.Errorf("%s is empty", filename)
	}
	if len(content) > maxMIBFileBytes {
		return filename, fmt.Errorf("%s is larger than %d bytes", filename, maxMIBFileBytes)
	}
	if !utf8.ValidString(content) {
		return filename, fmt.Errorf("%s is not valid UTF-8 text", filename)
	}
	if len(gomib.ScanModuleNames([]byte(content))) == 0 {
		return filename, fmt.Errorf("%s does not look like a MIB file (missing DEFINITIONS ::= header)", filename)
	}
	return filename, nil
}

func assignMIBFileCounts(files []store.MIBFile, symbols []store.MIBSymbol) {
	counts := make(map[string]int)
	for _, symbol := range symbols {
		counts[symbol.Module]++
	}
	for index := range files {
		modules := gomib.ScanModuleNames([]byte(files[index].Content))
		sort.Strings(modules)
		files[index].Modules = modules
		files[index].SizeBytes = len(files[index].Content)
		total := 0
		for _, module := range modules {
			total += counts[module]
		}
		files[index].SymbolCount = total
	}
}

func (s *Server) handleListMIBs(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.MIBSummary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleSearchMIBSymbols(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	symbols, err := s.store.ListMIBSymbols(r.URL.Query().Get("q"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if symbols == nil {
		symbols = []store.MIBSymbol{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"symbols": symbols})
}

func (s *Server) handleImportMIBs(w http.ResponseWriter, r *http.Request) {
	var request mibImportRequest
	if err := decodeJSONLimit(w, r, &request, maxMIBUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON or MIB upload too large: "+err.Error())
		return
	}
	if len(request.Files) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one MIB file")
		return
	}
	if len(request.Files) > maxMIBUploadFiles {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("import at most %d MIB files at once", maxMIBUploadFiles))
		return
	}
	s.mibMu.Lock()
	defer s.mibMu.Unlock()

	existing, err := s.store.ListMIBFilesWithContent()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byName := make(map[string]store.MIBFile, len(existing)+len(request.Files))
	for _, file := range existing {
		byName[file.Filename] = file
	}
	totalBytes := 0
	for _, file := range existing {
		totalBytes += len(file.Content)
	}
	seen := make(map[string]bool)
	for _, incoming := range request.Files {
		filename, err := validateMIBUpload(incoming.Filename, incoming.Content)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if seen[filename] {
			writeError(w, http.StatusBadRequest, "duplicate MIB filename: "+filename)
			return
		}
		seen[filename] = true
		if previous, ok := byName[filename]; ok {
			totalBytes -= len(previous.Content)
		}
		totalBytes += len(incoming.Content)
		if totalBytes > maxMIBLibraryBytes {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("MIB library would exceed %d bytes", maxMIBLibraryBytes))
			return
		}
		byName[filename] = store.MIBFile{
			Filename:   filename,
			Content:    incoming.Content,
			SizeBytes:  len(incoming.Content),
			ImportedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
	}
	files := make([]store.MIBFile, 0, len(byName))
	for _, file := range byName {
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Filename < files[j].Filename })
	parsed, err := parseMIBFiles(r.Context(), files)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assignMIBFileCounts(files, parsed.Symbols)
	if err := s.store.ReplaceMIBState(files, parsed.Symbols); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "mib-import", "mib", "library",
		fmt.Sprintf("files=%d symbols=%d modules=%s", len(files), len(parsed.Symbols),
			strings.Join(parsed.Modules, ", ")))
	summary, err := s.store.MIBSummary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": len(request.Files), "symbols": len(parsed.Symbols),
		"modules": parsed.Modules, "diagnostics": parsed.Diagnostics,
		"files": summary.Files, "symbol_count": summary.SymbolCount,
	})
}

func (s *Server) handleDeleteMIB(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid MIB id")
		return
	}
	s.mibMu.Lock()
	defer s.mibMu.Unlock()
	files, err := s.store.ListMIBFilesWithContent()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	remaining := make([]store.MIBFile, 0, len(files))
	found := false
	for _, file := range files {
		if file.ID == id {
			found = true
			continue
		}
		remaining = append(remaining, file)
	}
	if !found {
		writeError(w, http.StatusNotFound, "MIB file not found")
		return
	}
	parsed, err := parseMIBFiles(r.Context(), remaining)
	if err != nil && len(remaining) > 0 {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assignMIBFileCounts(remaining, parsed.Symbols)
	if err := s.store.ReplaceMIBState(remaining, parsed.Symbols); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "mib-delete", "mib", strconv.FormatInt(id, 10), "deleted")
	summary, err := s.store.MIBSummary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// resolveSNMPOIDValue accepts a numeric OID or an imported MIB symbol. Scalar
// symbols get the .0 instance automatically; columns require an explicit
// instance suffix.
func (s *Server) resolveSNMPOIDValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("SNMP OID is empty")
	}
	if snmpOIDPattern.MatchString(value) {
		return normalizeOID(value), nil
	}
	module := ""
	name := value
	if index := strings.Index(name, "::"); index >= 0 {
		module = strings.TrimSpace(name[:index])
		name = strings.TrimSpace(name[index+2:])
	}
	suffix := ""
	if index := strings.IndexByte(name, '.'); index > 0 {
		suffix = name[index:]
		name = name[:index]
		if !mibInstanceSuffixPattern.MatchString(suffix) {
			return "", fmt.Errorf("invalid SNMP instance suffix %q", suffix)
		}
	}
	if name == "" {
		return "", fmt.Errorf("invalid SNMP OID or MIB symbol %q", value)
	}
	symbol, err := s.store.LookupMIBSymbolByName(name, module)
	if err != nil {
		return "", fmt.Errorf("unknown SNMP OID or MIB symbol %q", value)
	}
	kind := strings.ToLower(symbol.Kind)
	if kind != "scalar" && kind != "column" {
		return "", fmt.Errorf("MIB symbol %q is a %s, not a scalar or column", value, symbol.Kind)
	}
	if suffix == "" {
		if kind == "scalar" {
			suffix = ".0"
		} else {
			return "", fmt.Errorf("MIB symbol %q is a table column; add an instance suffix such as %s.1", value, value)
		}
	}
	return normalizeOID(symbol.OID + suffix), nil
}

func (s *Server) normalizeSNMPOIDList(value string) (string, error) {
	parts := settingUnitSeparator.Split(strings.TrimSpace(value), -1)
	oids := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		oid, err := s.resolveSNMPOIDValue(part)
		if err != nil {
			return "", err
		}
		if seen[oid] {
			continue
		}
		seen[oid] = true
		oids = append(oids, "."+oid)
	}
	return strings.Join(oids, ", "), nil
}

// enrichSNMPValues adds MIB names, syntax, and enum labels to stored values.
func (s *Server) enrichSNMPValues(values []store.SNMPValue) {
	for index := range values {
		symbol, err := s.store.LookupMIBSymbolByOID(values[index].OID)
		if err != nil {
			continue
		}
		values[index].Name = symbol.Name
		values[index].Syntax = symbol.Syntax
		if len(symbol.Enums) > 0 {
			if value, err := strconv.ParseInt(values[index].Value, 10, 64); err == nil {
				for _, enum := range symbol.Enums {
					if enum.Value == value {
						values[index].EnumLabel = enum.Label
						break
					}
				}
			}
		}
	}
}
