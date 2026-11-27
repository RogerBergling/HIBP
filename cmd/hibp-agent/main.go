// Command hibp-agent is the optional cross-platform monitoring agent.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/RogerBergling/hibp/internal/buildinfo"
)

type agentServices struct {
	Running []string `json:"running"`
	Failed  []string `json:"failed"`
}

type agentSnapshot struct {
	Facts    json.RawMessage `json:"facts,omitempty"`
	Services *agentServices  `json:"services,omitempty"`
	Docker   json.RawMessage `json:"docker,omitempty"`
}

func main() {
	var (
		server   = flag.String("server", "", "HIBP base URL, for example https://hibp.lan:8443")
		token    = flag.String("token", "", "agent token created in HIBP")
		interval = flag.Duration("interval", 5*time.Minute, "collection interval")
		once     = flag.Bool("once", false, "collect and send once, then exit")
		insecure = flag.Bool("insecure-skip-verify", false, "skip TLS verification (internal lab only)")
	)
	flag.Parse()
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "hibp-agent: --server and --token are required")
		os.Exit(2)
	}
	if *interval < 30*time.Second {
		*interval = 30 * time.Second
	}
	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure},
		},
	}
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		snapshot, events, err := collect(ctx)
		if err != nil {
			log.Printf("collect: %v", err)
			return
		}
		if err := post(client, *server, *token, "/api/v1/agent/v1/heartbeat", map[string]any{
			"platform": runtime.GOOS, "version": buildinfo.Current.Version,
		}); err != nil {
			log.Printf("heartbeat: %v", err)
		}
		if snapshot != nil {
			if err := post(client, *server, *token, "/api/v1/agent/v1/snapshot", snapshot); err != nil {
				log.Printf("snapshot: %v", err)
			}
		}
		if len(events) > 0 {
			if err := post(client, *server, *token, "/api/v1/agent/v1/events", map[string]any{"events": events}); err != nil {
				log.Printf("events: %v", err)
			}
		}
	}
	run()
	if *once {
		return
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

func post(client *http.Client, server, token, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", response.Status, string(raw))
	}
	return nil
}
