package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// C30 fixture-driven integration proof. Every step talks to the real loopback engine over HTTP,
// uses the real durable storage adapter, signs a real Ed25519 bundle, forwards to the real owned
// synthetic upstream and then restarts the process to prove restore behavior.

type c30Step struct {
	StepID   string                 `json:"step_id"`
	Stage    string                 `json:"stage"`
	Endpoint string                 `json:"endpoint"`
	Method   string                 `json:"method"`
	Body     map[string]interface{} `json:"body"`
	Expected map[string]interface{} `json:"expected"`
}

type c30Fixture struct {
	FixtureID string    `json:"fixture_id"`
	Steps     []c30Step `json:"steps"`
}

func loadC30Fixture(t *testing.T, name string) c30Fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "policyhelix", "C30", name))
	if err != nil {
		t.Fatalf("failed to read C30 fixture %s: %v", name, err)
	}
	var fx c30Fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("malformed C30 fixture %s: %v", name, err)
	}
	if fx.FixtureID == "" || len(fx.Steps) == 0 {
		t.Fatalf("C30 fixture %s has no identity or steps", name)
	}
	return fx
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate a loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func waitForEngine(t *testing.T, baseURL string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("engine did not become healthy at %s", baseURL)
}

func callC30(t *testing.T, baseURL, method, endpoint string, body map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	var reader io.Reader
	if method != http.MethodGet {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to encode request body for %s: %v", endpoint, err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, baseURL+endpoint, reader)
	if err != nil {
		t.Fatalf("failed to build request %s: %v", endpoint, err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, endpoint, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]interface{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("response from %s is not JSON: %v (%s)", endpoint, err, string(raw))
		}
	}
	return resp.StatusCode, decoded
}

func substituteC30(value string, sessions map[string]string) string {
	if value == "$SESSION" {
		return sessions["SESSION"]
	}
	if value == "$SESSION_ACTIVE" {
		return sessions["SESSION_ACTIVE"]
	}
	return value
}

func runC30Fixture(t *testing.T, baseURL string, fx c30Fixture, sessions map[string]string) {
	t.Helper()
	for _, step := range fx.Steps {
		body := make(map[string]interface{}, len(step.Body))
		for k, v := range step.Body {
			if s, ok := v.(string); ok {
				body[k] = substituteC30(s, sessions)
			} else {
				body[k] = v
			}
		}
		status, res := callC30(t, baseURL, step.Method, step.Endpoint, body)

		expectedStatus := int(step.Expected["http_status"].(float64))
		if status != expectedStatus {
			t.Fatalf("%s %s: expected HTTP %d, got %d (%v)", step.StepID, step.Endpoint, expectedStatus, status, res)
		}
		for key, want := range step.Expected {
			if key == "http_status" {
				continue
			}
			got, ok := res[key]
			switch key {
			case "decision_allow":
				decision, _ := res["decision"].(map[string]interface{})
				got, ok = decision["allow"], decision != nil
			case "active_bundle_present":
				_, present := res["active_bundle"]
				got, ok = present, true
			case "revoked_session_present":
				ids, _ := res["revoked_session_ids"].([]interface{})
				got, ok = len(ids) > 0, true
			case "upstream_ready":
				upstream, _ := res["upstream"].(map[string]interface{})
				got, ok = upstream["ready"], upstream != nil
			case "provider_count":
				providers, _ := res["providers"].([]interface{})
				got, ok = len(providers), true
			}
			if !ok {
				t.Fatalf("%s %s: expected field %q is missing from the response: %v", step.StepID, step.Endpoint, key, res)
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("%s %s: field %q expected %v, got %v", step.StepID, step.Endpoint, key, want, got)
			}
		}

		switch step.Stage {
		case "session":
			if id, ok := res["session_id"].(string); ok && id != "" {
				sessions["SESSION"] = id
			}
		case "outage-session":
			if id, ok := res["session_id"].(string); ok && id != "" {
				sessions["SESSION_ACTIVE"] = id
			}
		}
	}
}

func TestC30ReferenceWorkflowRestartAndRestore(t *testing.T) {
	storageDir := t.TempDir()
	port := freeLoopbackPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	sessions := map[string]string{}

	stopCh := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runServer("127.0.0.1", port, storageDir, stopCh) }()
	waitForEngine(t, baseURL)

	workflow := loadC30Fixture(t, "positive-reference-workflow.json")
	runC30Fixture(t, baseURL, workflow, sessions)
	if sessions["SESSION"] == "" || sessions["SESSION_ACTIVE"] == "" {
		t.Fatalf("workflow did not issue both reference sessions")
	}

	// Negative cases run against the same live workflow state.
	for _, name := range []string{
		"negative-spoofed-header.json",
		"negative-direct-origin.json",
		"negative-revoked-session.json",
		"negative-provider-unavailable.json",
		"negative-expired-bundle.json",
		"negative-malformed-fixture.json",
	} {
		runC30Fixture(t, baseURL, loadC30Fixture(t, name), sessions)
	}

	close(stopCh)
	if err := <-done; err != nil {
		t.Fatalf("engine shutdown failed: %v", err)
	}

	// Restart against the same durable storage directory and prove restore.
	port = freeLoopbackPort(t)
	baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	stopCh = make(chan struct{})
	done = make(chan error, 1)
	go func() { done <- runServer("127.0.0.1", port, storageDir, stopCh) }()
	waitForEngine(t, baseURL)

	runC30Fixture(t, baseURL, loadC30Fixture(t, "positive-restart-restore.json"), sessions)

	close(stopCh)
	if err := <-done; err != nil {
		t.Fatalf("engine shutdown after restart failed: %v", err)
	}
}

func TestC30ReferenceRuntimeRequiresDurableStorage(t *testing.T) {
	port := freeLoopbackPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	stopCh := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runServer("127.0.0.1", port, "", stopCh) }()
	waitForEngine(t, baseURL)
	defer func() {
		close(stopCh)
		<-done
	}()

	fx := loadC30Fixture(t, "negative-unavailable-runtime.json")
	step := fx.Steps[0]
	status, res := callC30(t, baseURL, step.Method, step.Endpoint, step.Body)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503 without durable storage, got %d (%v)", status, res)
	}
	if res["error"] != "REFERENCE_RUNTIME_UNAVAILABLE" {
		t.Fatalf("expected explicit REFERENCE_RUNTIME_UNAVAILABLE error, got %v", res)
	}
	if ready, _ := res["ready"].(bool); ready {
		t.Fatalf("unavailable runtime must not report ready")
	}
}

func snapshotStorageDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		content, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		files[rel] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to snapshot dir: %v", err)
	}
	return files
}

func TestC30ReadinessProbeIsReadOnly(t *testing.T) {
	storageDir := t.TempDir()
	port := freeLoopbackPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	stopCh := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runServer("127.0.0.1", port, storageDir, stopCh) }()
	waitForEngine(t, baseURL)
	defer func() {
		close(stopCh)
		<-done
	}()

	snapBefore := snapshotStorageDir(t, storageDir)

	// Probe readyz and api/v1/runtime/readiness repeatedly
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 10; i++ {
		resp, err := client.Get(baseURL + "/readyz?check=engine")
		if err != nil {
			t.Fatalf("readiness probe %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("readiness probe %d returned status %d", i, resp.StatusCode)
		}

		resp2, err2 := client.Get(baseURL + "/api/v1/runtime/readiness")
		if err2 != nil {
			t.Fatalf("runtime readiness %d failed: %v", i, err2)
		}
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("runtime readiness %d returned status %d", i, resp2.StatusCode)
		}
	}

	snapAfter := snapshotStorageDir(t, storageDir)

	if len(snapBefore) != len(snapAfter) {
		t.Fatalf("readiness probe modified file count: before %d, after %d", len(snapBefore), len(snapAfter))
	}
	for k, vBefore := range snapBefore {
		vAfter, exists := snapAfter[k]
		if !exists {
			t.Fatalf("file %s deleted by readiness probe", k)
		}
		if vBefore != vAfter {
			t.Fatalf("file %s mutated by readiness probe", k)
		}
	}
}

func TestC30SessionIssuanceRejectsClientSessionID(t *testing.T) {
	storageDir := t.TempDir()
	port := freeLoopbackPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	stopCh := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runServer("127.0.0.1", port, storageDir, stopCh) }()
	waitForEngine(t, baseURL)
	defer func() {
		close(stopCh)
		<-done
	}()

	status, res := callC30(t, baseURL, http.MethodPost, "/api/v1/reference/session", map[string]interface{}{
		"session_id": "malicious-fixed-session-id",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("expected HTTP 422 Unprocessable Entity, got %d (%v)", status, res)
	}
	if valid, _ := res["valid"].(bool); valid {
		t.Fatalf("session must not be valid when client supplies session_id")
	}
	if res["error_code"] != "INVALID_SESSION_REQUEST" {
		t.Fatalf("expected error_code INVALID_SESSION_REQUEST, got %v", res["error_code"])
	}
}

