package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/RogerBergling/hibp/internal/store"
)

func postCMDBImport(t *testing.T, url string, requestBody cmdbImportRequest) cmdbImportResult {
	t.Helper()
	payload, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, url, "test-token", string(payload))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CMDB import failed: %d %s", resp.StatusCode, body)
	}
	var result cmdbImportResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCMDBImportCSVMergeAndCreate(t *testing.T) {
	ts, db := testServer(t)
	existing, err := db.CreateHost(store.Host{
		Name: "old-web", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", GroupName: "old-group",
		Tags: "old", CMDBCIID: "CI-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	data := `name,address,port,username,auth_type,key_path,group,tags,cmdb_ci_id,external_id
web01,10.0.0.10,22,ubuntu,key,/home/ops/.ssh/id_ed25519,web-prod,"web,prod",CI-1,EXT-1
db01,10.0.0.20,22,root,key,/home/ops/.ssh/id_ed25519,db-prod,"db,prod",CI-2,EXT-2`
	preview := postCMDBImport(t, ts.URL+"/api/v1/cmdb/import", cmdbImportRequest{
		Data: data, Format: "auto", Mode: "merge", Commit: false,
	})
	if preview.Format != "csv" || len(preview.Rows) != 2 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if preview.Rows[0].Action != "update" || preview.Rows[0].MatchedBy != "cmdb_ci_id" || preview.Rows[0].HostID != existing.ID {
		t.Fatalf("expected existing host match: %+v", preview.Rows[0])
	}
	if preview.Rows[1].Action != "create" {
		t.Fatalf("expected new host create: %+v", preview.Rows[1])
	}

	committed := postCMDBImport(t, ts.URL+"/api/v1/cmdb/import", cmdbImportRequest{
		Data: data, Format: "csv", Mode: "merge", Commit: true,
	})
	if committed.Created != 1 || committed.Updated != 1 || committed.Skipped != 0 {
		t.Fatalf("unexpected commit counts: %+v", committed)
	}
	updated, err := db.GetHost(existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "web01" || updated.GroupName != "web-prod" || updated.Tags != "web,prod" || updated.CMDBCIID != "CI-1" {
		t.Fatalf("unexpected merged host: %+v", updated)
	}
	created, err := db.FindHostByAddress("10.0.0.20", 22)
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "db01" || created.Username != "root" || created.AuthType != "key" || created.CMDBCIID != "CI-2" {
		t.Fatalf("unexpected imported host: %+v", created)
	}
}

func TestCMDBImportJSONOverwriteAndErrors(t *testing.T) {
	ts, db := testServer(t)
	existing, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", GroupName: "web-prod",
		Tags: "web,prod", OSFamily: "Linux", OSVersion: "old", CMDBCIID: "CI-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	data := `{"cis":[
		{"ci_id":"CI-1","ci_name":"web01 updated","attributes":{"ip_address":"10.0.0.11","ssh_username":"ubuntu","ssh_auth_type":"key","ssh_key_path":"/home/ops/.ssh/id_ed25519","group":"","tags":"web,prod,updated"},"custom":{"os_family":"Linux","os_version":"Ubuntu 24.04"},"external_id":"EXT-1"},
		{"ci_id":"CI-3","ci_name":"bad","attributes":{"ip_address":"10.0.0.30"},"custom":{"os_family":"Linux"}}
	]}`
	preview := postCMDBImport(t, ts.URL+"/api/v1/cmdb/import", cmdbImportRequest{
		Data: data, Format: "json", Mode: "overwrite", Commit: false,
	})
	if preview.Format != "json" || len(preview.Rows) != 2 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if preview.Rows[0].Action != "update" || preview.Rows[0].MatchedBy != "cmdb_ci_id" {
		t.Fatalf("expected JSON update: %+v", preview.Rows[0])
	}
	if preview.Rows[1].Action != "error" || len(preview.Problems) != 1 {
		t.Fatalf("expected validation error: %+v", preview)
	}

	committed := postCMDBImport(t, ts.URL+"/api/v1/cmdb/import", cmdbImportRequest{
		Data: data, Format: "json", Mode: "overwrite", Commit: true,
	})
	if committed.Created != 0 || committed.Updated != 1 || committed.Skipped != 1 {
		t.Fatalf("unexpected commit counts: %+v", committed)
	}
	updated, err := db.GetHost(existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "web01 updated" || updated.Address != "10.0.0.11" || updated.GroupName != "" || updated.Tags != "web,prod,updated" {
		t.Fatalf("unexpected overwritten host: %+v", updated)
	}
	if updated.OSFamily != "Linux" || updated.OSVersion != "Ubuntu 24.04" {
		t.Fatalf("OS fields were not imported: %+v", updated)
	}
	if updated.CMDBCIID != "CI-1" {
		t.Fatalf("CMDB id changed unexpectedly: %+v", updated)
	}
}

func TestCMDBImportRejectsInvalidModeAndData(t *testing.T) {
	ts, _ := testServer(t)
	payload, _ := json.Marshal(cmdbImportRequest{Data: "name,address\nweb01,10.0.0.10", Mode: "replace", Commit: false})
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/cmdb/import", "test-token", string(payload))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected mode validation failure, got %d %s", resp.StatusCode, body)
	}
}
