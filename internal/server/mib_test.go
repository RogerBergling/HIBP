package server

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/RogerBergling/hibp/internal/store"
)

const testMIB = `HIBP-TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, Counter32, enterprises
        FROM SNMPv2-SMI;

hibpTestMIB MODULE-IDENTITY
    LAST-UPDATED "202611270000Z"
    ORGANIZATION "HIBP"
    CONTACT-INFO "test"
    DESCRIPTION "Test MIB for HIBP."
    ::= { enterprises 99999 }

hibpTestObjects OBJECT IDENTIFIER ::= { hibpTestMIB 1 }

hibpTestStatus OBJECT-TYPE
    SYNTAX INTEGER { up(1), down(2), testing(3) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Test status."
    ::= { hibpTestObjects 1 }

hibpTestName OBJECT-TYPE
    SYNTAX OCTET STRING (SIZE (0..64))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Test name."
    ::= { hibpTestObjects 2 }

hibpTestCounter OBJECT-TYPE
    SYNTAX Counter32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Test counter."
    ::= { hibpTestObjects 3 }

END
`

const testMIBBase = `HIBP-BASE-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, enterprises
        FROM SNMPv2-SMI;

hibpBase MODULE-IDENTITY
    LAST-UPDATED "202611270000Z"
    ORGANIZATION "HIBP"
    CONTACT-INFO "test"
    DESCRIPTION "Base MIB for dependency tests."
    ::= { enterprises 99998 }

hibpBaseObjects OBJECT IDENTIFIER ::= { hibpBase 1 }

END
`

const testMIBChild = `HIBP-CHILD-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI
    hibpBaseObjects
        FROM HIBP-BASE-MIB;

hibpChild MODULE-IDENTITY
    LAST-UPDATED "202611270000Z"
    ORGANIZATION "HIBP"
    CONTACT-INFO "test"
    DESCRIPTION "Child MIB for dependency tests."
    ::= { hibpBaseObjects 1 }

hibpChildValue OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Child value."
    ::= { hibpChild 1 }

END
`

func TestParseMIBFilesWithDependency(t *testing.T) {
	result, err := parseMIBFiles(context.Background(), []store.MIBFile{
		{Filename: "HIBP-BASE-MIB.mib", Content: testMIBBase},
		{Filename: "HIBP-CHILD-MIB.mib", Content: testMIBChild},
	})
	if err != nil {
		t.Fatal(err)
	}
	var child *store.MIBSymbol
	for index := range result.Symbols {
		if result.Symbols[index].Name == "hibpChildValue" {
			child = &result.Symbols[index]
			break
		}
	}
	if child == nil || child.OID != "1.3.6.1.4.1.99998.1.1.1" || child.Kind != "scalar" {
		t.Fatalf("unexpected child symbol: %+v", child)
	}
	if len(result.Modules) != 2 {
		t.Fatalf("unexpected modules: %+v", result.Modules)
	}
}

func TestParseMIBFilesMissingDependency(t *testing.T) {
	if _, err := parseMIBFiles(context.Background(), []store.MIBFile{{
		Filename: "HIBP-CHILD-MIB.mib",
		Content:  testMIBChild,
	}}); err == nil {
		t.Fatal("expected missing MIB dependency to fail")
	}
}

func TestParseMIBFiles(t *testing.T) {
	result, err := parseMIBFiles(context.Background(), []store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Modules) != 1 || result.Modules[0] != "HIBP-TEST-MIB" {
		t.Fatalf("unexpected modules: %+v", result.Modules)
	}
	var status, name, counter *store.MIBSymbol
	for index := range result.Symbols {
		symbol := &result.Symbols[index]
		switch symbol.Name {
		case "hibpTestStatus":
			status = symbol
		case "hibpTestName":
			name = symbol
		case "hibpTestCounter":
			counter = symbol
		}
	}
	if status == nil || name == nil || counter == nil {
		t.Fatalf("missing symbols: %+v", result.Symbols)
	}
	if status.OID != "1.3.6.1.4.1.99999.1.1" || status.Kind != "scalar" || status.Syntax != "INTEGER" {
		t.Fatalf("unexpected status symbol: %+v", status)
	}
	if len(status.Enums) != 3 || status.Enums[1].Label != "down" || status.Enums[1].Value != 2 {
		t.Fatalf("unexpected enums: %+v", status.Enums)
	}
	if name.OID != "1.3.6.1.4.1.99999.1.2" || counter.OID != "1.3.6.1.4.1.99999.1.3" {
		t.Fatalf("unexpected scalar OIDs: %+v %+v", name, counter)
	}
}

func TestResolveMIBOIDValue(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	result, err := parseMIBFiles(context.Background(), []store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReplaceMIBState([]store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}}, result.Symbols); err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"hibpTestStatus":                 "1.3.6.1.4.1.99999.1.1.0",
		"HIBP-TEST-MIB::hibpTestStatus":  "1.3.6.1.4.1.99999.1.1.0",
		"hibpTestStatus.7":               "1.3.6.1.4.1.99999.1.1.7",
		".1.3.6.1.2.1.1.3.0":             "1.3.6.1.2.1.1.3.0",
		"HIBP-TEST-MIB::hibpTestCounter": "1.3.6.1.4.1.99999.1.3.0",
	}
	for input, want := range tests {
		got, err := app.resolveSNMPOIDValue(input)
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if got != want {
			t.Fatalf("%q: got %q, want %q", input, got, want)
		}
	}
	if _, err := app.resolveSNMPOIDValue("hibpTestObjects"); err == nil {
		t.Fatal("expected non-scalar MIB symbol to be rejected")
	}
	if _, err := app.resolveSNMPOIDValue("missingSymbol"); err == nil {
		t.Fatal("expected unknown MIB symbol to be rejected")
	}
}

func TestNormalizeSNMPOIDListNames(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	result, err := parseMIBFiles(context.Background(), []store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReplaceMIBState([]store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}}, result.Symbols); err != nil {
		t.Fatal(err)
	}
	normalized, err := app.normalizeSNMPOIDList("hibpTestStatus, hibpTestCounter .1.3.6.1.2.1.1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	want := ".1.3.6.1.4.1.99999.1.1.0, .1.3.6.1.4.1.99999.1.3.0, .1.3.6.1.2.1.1.5.0"
	if normalized != want {
		t.Fatalf("got %q, want %q", normalized, want)
	}
}

func TestEnrichSNMPValuesFromMIB(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	result, err := parseMIBFiles(context.Background(), []store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReplaceMIBState([]store.MIBFile{{
		Filename: "HIBP-TEST-MIB.mib",
		Content:  testMIB,
	}}, result.Symbols); err != nil {
		t.Fatal(err)
	}
	values := []store.SNMPValue{{OID: "1.3.6.1.4.1.99999.1.1.0", Value: "2"}}
	app.enrichSNMPValues(values)
	if values[0].Name != "hibpTestStatus" || values[0].EnumLabel != "down" || values[0].Syntax != "INTEGER" {
		t.Fatalf("unexpected enriched value: %+v", values[0])
	}
}

func TestSNMPSettingsAcceptMIBName(t *testing.T) {
	ts, db := testServer(t)
	payload := `{"files":[{"filename":"HIBP-TEST-MIB.mib","content":` + jsonString(testMIB) + `}]}`
	resp := request(t, "POST", ts.URL+"/api/v1/snmp/mibs", "test-token", payload)
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("import failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	resp = request(t, "PUT", ts.URL+"/api/v1/settings", "test-token",
		`{"scope":"fleet","settings":{"snmp.oids":"hibpTestStatus, hibpTestCounter"}}`)
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("settings update failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	value, err := db.GetSetting("fleet", "snmp.oids")
	if err != nil {
		t.Fatal(err)
	}
	if value != ".1.3.6.1.4.1.99999.1.1.0, .1.3.6.1.4.1.99999.1.3.0" {
		t.Fatalf("unexpected normalized OIDs: %q", value)
	}
}

func TestSNMPValueMonitorAcceptsMIBName(t *testing.T) {
	ts, db := testServer(t)
	payload := `{"files":[{"filename":"HIBP-TEST-MIB.mib","content":` + jsonString(testMIB) + `}]}`
	resp := request(t, "POST", ts.URL+"/api/v1/snmp/mibs", "test-token", payload)
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("import failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	host, err := db.CreateHost(store.Host{Name: "udm", Address: "192.168.4.1", AuthType: "network"})
	if err != nil {
		t.Fatal(err)
	}
	monitorPayload := `{"name":"UDM status","type":"snmp.value","target":"hibpTestStatus","warning":1,"critical":2,"interval_seconds":60,"assignments":[{"scope":"host","target":"` + host.ID + `"}]}`
	resp = request(t, "POST", ts.URL+"/api/v1/monitors", "test-token", monitorPayload)
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("monitor create failed: %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.Target != "1.3.6.1.4.1.99999.1.1.0" {
		t.Fatalf("unexpected monitor target: %q", created.Target)
	}
}

func TestMIBImportAPI(t *testing.T) {
	ts, db := testServer(t)
	payload := `{"files":[{"filename":"HIBP-TEST-MIB.mib","content":` + jsonString(testMIB) + `}]}`
	resp := request(t, "POST", ts.URL+"/api/v1/snmp/mibs", "test-token", payload)
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("import failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	summary, err := db.MIBSummary()
	if err != nil || len(summary.Files) != 1 || summary.SymbolCount == 0 {
		t.Fatalf("unexpected MIB summary: %+v %v", summary, err)
	}
	resp = request(t, "GET", ts.URL+"/api/v1/snmp/oids?q=hibpTestStatus", "test-token", "")
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		t.Fatalf("search failed: %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(raw), "hibpTestStatus") || !strings.Contains(string(raw), "1.3.6.1.4.1.99999.1.1") {
		t.Fatalf("unexpected search response: %s", raw)
	}
	resp = request(t, "DELETE", ts.URL+"/api/v1/snmp/mibs/"+strconv.FormatInt(summary.Files[0].ID, 10), "test-token", "")
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		t.Fatalf("delete failed: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	summary, err = db.MIBSummary()
	if err != nil || len(summary.Files) != 0 || summary.SymbolCount != 0 {
		t.Fatalf("unexpected summary after delete: %+v %v", summary, err)
	}
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
