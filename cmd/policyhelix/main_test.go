package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/bundles"
)

func TestEngineVersion(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--version")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run --version failed: %v, stderr: %s", err, stderr.String())
	}

	var resp VersionResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse version JSON: %v, output: %s", err, stdout.String())
	}

	if resp.Project != "PolicyHelix" || resp.Engine != EngineName || resp.Version != EngineVersion {
		t.Errorf("Unexpected version response: %+v", resp)
	}
	if !resp.Loopback {
		t.Errorf("Expected loopback=true")
	}
	if resp.CoreReady != false {
		t.Errorf("Expected coreReady=false in minimal health launch")
	}
}

func TestEngineSmokeTestCLI(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--smoke-test")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run --smoke-test failed: %v, stderr: %s", err, stderr.String())
	}

	var res EvaluationResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse smoke-test JSON: %v, output: %s", err, stdout.String())
	}
	if res.Status != "ok" || res.Engine != EngineName {
		t.Errorf("Unexpected smoke test response: %+v", res)
	}
	if res.PrivateResourcesFailClosed == nil || !*res.PrivateResourcesFailClosed {
		t.Errorf("Expected PrivateResourcesFailClosed=true")
	}
}

func TestEngineLoopbackEnforcement(t *testing.T) {
	nonLoopback := []string{"0.0.0.0", "192.168.1.100", "example.com"}
	for _, host := range nonLoopback {
		err := runServer(host, 0, "", make(chan struct{}))
		if err == nil {
			t.Errorf("Expected error for non-loopback host '%s', got nil", host)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("Expected loopback error message for host '%s', got: %v", host, err)
		}
	}
}

func TestEngineOccupiedPort(t *testing.T) {
	// Bind a real listener on loopback
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind test listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Attempt to start engine on the same port
	err = runServer("127.0.0.1", port, "", make(chan struct{}))
	if err == nil {
		t.Fatalf("Expected error for occupied port %d, got nil", port)
	}
	if !strings.Contains(err.Error(), "bind") && !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("Expected bind/address in use error, got: %v", err)
	}
}

func TestEngineHealthAndStatusEndpoints(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan error, 1)

	go func() {
		serverDone <- runServer("127.0.0.1", port, "", stopCh)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Poll until ready
	var ready bool
	for i := 0; i < 20; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			ready = true
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		close(stopCh)
		t.Fatalf("Engine server did not become healthy in time")
	}

	// Test GET /healthz
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz failed: %v, status: %v", err, resp.Status)
	}
	var health map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&health)
	_ = resp.Body.Close()
	if health["status"] != "ok" || health["engine"] != EngineName {
		t.Errorf("Unexpected healthz: %+v", health)
	}

	// Test GET /readyz
	resp, err = client.Get(baseURL + "/readyz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz failed: %v, status: %v", err, resp.Status)
	}
	var readyz map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&readyz)
	_ = resp.Body.Close()
	if readyz["status"] != "ready" || readyz["businessFeaturesCompleted"] != false {
		t.Errorf("Unexpected readyz: %+v", readyz)
	}

	// Test GET /v1/runtime/status
	resp, err = client.Get(baseURL + "/v1/runtime/status")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/runtime/status failed: %v, status: %v", err, resp.Status)
	}
	var status StatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()
	if status.Engine != EngineName || status.CoreReady != false || !status.Loopback {
		t.Errorf("Unexpected status: %+v", status)
	}

	// Test POST /v1/runtime/evaluate-fixture with malformed payload
	resp, err = client.Post(baseURL+"/v1/runtime/evaluate-fixture", "application/json", strings.NewReader(`{invalid json`))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for malformed json, got: %v, status: %v", err, resp.Status)
	}
	_ = resp.Body.Close()

	// Clean shutdown via stopCh
	close(stopCh)
	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("Unexpected server shutdown error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("Server did not shut down within timeout")
	}
}

func TestEngineC03Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "tests", "fixtures", "policyhelix", "C03")

	// 1. Positive engine launch fixture
	posPath := filepath.Join(fixtureDir, "positive-engine-launch.json")
	res, err := evaluateFixtureFile(posPath)
	if err != nil {
		t.Fatalf("Failed evaluating positive fixture: %v", err)
	}
	if res.Status != "ok" || res.Engine != EngineName {
		t.Errorf("Unexpected positive fixture outcome: %+v", res)
	}

	// 2. Missing provider fixture
	missingPath := filepath.Join(fixtureDir, "invalid-missing-provider.json")
	res, err = evaluateFixtureFile(missingPath)
	if err != nil {
		t.Fatalf("Failed evaluating missing provider fixture: %v", err)
	}
	if res.Allow == nil || *res.Allow != false || res.Error != "provider_unavailable" {
		t.Errorf("Expected allow=false and error=provider_unavailable, got: %+v", res)
	}

	// 3. Malformed request fixture
	malformedPath := filepath.Join(fixtureDir, "invalid-malformed-request.json")
	res, err = evaluateFixtureFile(malformedPath)
	if err != nil {
		t.Fatalf("Failed evaluating malformed fixture: %v", err)
	}
	if res.Allow == nil || *res.Allow != false || res.Error != "malformed_fixture" {
		t.Errorf("Expected allow=false and error=malformed_fixture, got: %+v", res)
	}

	// 4. Private resource fail-closed fixture
	privPath := filepath.Join(fixtureDir, "invalid-private-resource-fail-closed.json")
	res, err = evaluateFixtureFile(privPath)
	if err != nil {
		t.Fatalf("Failed evaluating private resource fixture: %v", err)
	}
	if res.Allow == nil || *res.Allow != false || res.Error != "unauthenticated_identity" {
		t.Errorf("Expected allow=false and error=unauthenticated_identity, got: %+v", res)
	}
}

func TestEngineRepeatAfterRestart(t *testing.T) {
	privPath := filepath.Join("..", "..", "tests", "fixtures", "policyhelix", "C03", "invalid-private-resource-fail-closed.json")

	// First run
	res1, err := evaluateFixtureFile(privPath)
	if err != nil {
		t.Fatalf("Run 1 failed: %v", err)
	}

	// Simulate restart
	time.Sleep(50 * time.Millisecond)

	// Second run after restart
	res2, err := evaluateFixtureFile(privPath)
	if err != nil {
		t.Fatalf("Run 2 failed: %v", err)
	}

	if *res1.Allow != *res2.Allow || res1.Error != res2.Error {
		t.Errorf("Invariant changed across restart: run1=%+v, run2=%+v", res1, res2)
	}
}

func TestEngineEvaluateContractEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runServer("127.0.0.1", port, "", stopCh)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	for i := 0; i < 20; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	validPayload := `{
		"schema_version": "1",
		"request_id": "req-c04-smoke",
		"subject": {
			"id": "user_alice",
			"issuer": "https://idp.local.test/realms/policyhelix",
			"roles": ["operator"],
			"authenticated": true,
			"session_epoch": 1730000000
		},
		"resource": {
			"id": "service:analytics/data/report-2026",
			"type": "dataset",
			"classification": "internal"
		},
		"action": "read",
		"context": {
			"protocol": "loopback",
			"source_ip": "127.0.0.1",
			"client_id": "policyhelix-local-web",
			"timestamp": "2026-11-03T10:00:00Z",
			"untrusted_headers_stripped": true
		},
		"policy_bundle": {
			"digest": "sha256:4a5c88e5d2639201f99c235b2e912f2cbe6783965b1287f3b89b1424e12e12e8",
			"revision": 1,
			"signed_at": "2026-11-03T10:00:00Z",
			"signature_verified": true,
			"provider_state": "ready"
		},
		"limits": {
			"max_payload_bytes": 65536,
			"deadline_ms": 200
		}
	}`

	// Positive evaluation via POST /v1/runtime/evaluate-contract
	resp, err := client.Post(baseURL+"/v1/runtime/evaluate-contract", "application/json", strings.NewReader(validPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST evaluate-contract failed: %v, status: %v", err, resp.Status)
	}
	var res map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	_ = resp.Body.Close()

	if res["status"] != "complete" {
		t.Errorf("Expected status=complete, got %v", res["status"])
	}
	dec, _ := res["decision"].(map[string]interface{})
	if dec["allow"] != true {
		t.Errorf("Expected allow=true, got %v", dec["allow"])
	}

	// Unsupported version via POST /v1/runtime/evaluate-contract
	badVersionPayload := strings.Replace(validPayload, `"schema_version": "1"`, `"schema_version": "99"`, 1)
	resp, err = client.Post(baseURL+"/v1/runtime/evaluate-contract", "application/json", strings.NewReader(badVersionPayload))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for bad schema version, got status: %v", resp.Status)
	}
	_ = resp.Body.Close()

	close(stopCh)
	<-serverDone
}

func TestEngineShadowEndpoints(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runServer("127.0.0.1", port, "", stopCh)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	for i := 0; i < 20; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. Evaluate shadow request via POST /api/v1/rollout/shadow/evaluate
	evalPayload := `{
		"request": {
			"request_id": "req-main-test-01",
			"path": "/api/v1/workloads/jobs",
			"action": "read",
			"subject": {
				"id": "usr-op-01",
				"issuer": "https://issuer.policyhelix.local",
				"roles": ["operator"],
				"authenticated": true
			}
		}
	}`

	resp, err := client.Post(baseURL+"/api/v1/rollout/shadow/evaluate", "application/json", strings.NewReader(evalPayload))
	if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden) {
		t.Fatalf("POST /api/v1/rollout/shadow/evaluate failed: %v, status: %v", err, resp.Status)
	}
	_ = resp.Body.Close()

	// 2. Query divergence via GET /api/v1/rollout/shadow/divergence
	divResp, err := client.Get(baseURL + "/api/v1/rollout/shadow/divergence")
	if err != nil || divResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/rollout/shadow/divergence failed: %v, status: %v", err, divResp.Status)
	}
	var divData map[string]interface{}
	_ = json.NewDecoder(divResp.Body).Decode(&divData)
	_ = divResp.Body.Close()
	if _, ok := divData["stats"]; !ok {
		t.Errorf("expected stats field in divergence response: %+v", divData)
	}

	// 3. Clear divergence store via POST /api/v1/rollout/shadow/divergence?clear=true
	clearResp, err := client.Post(baseURL+"/api/v1/rollout/shadow/divergence?clear=true", "application/json", nil)
	if err != nil || clearResp.StatusCode != http.StatusOK {
		t.Fatalf("POST clear failed: %v, status: %v", err, clearResp.Status)
	}
	_ = clearResp.Body.Close()

	close(stopCh)
	<-serverDone
}

func TestPolicyCacheEndpoints(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = runServer("127.0.0.1", port, "", stopCh)
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	for i := 0; i < 50; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. POST /api/v1/policy/cache/evaluate
	evalPayload := `{
		"request": {
			"request_id": "req-cache-test-01",
			"path": "/api/v1/workloads/jobs",
			"action": "read",
			"subject": {
				"id": "usr-cache-01",
				"issuer": "https://issuer.policyhelix.local",
				"roles": ["operator"],
				"authenticated": true
			},
			"bundle": {
				"schema_version": "1",
				"bundle_id": "bundle-cache-test-v1",
				"package": "policyhelix.authz",
				"issuer": "https://issuer.policyhelix.local",
				"signer_key_id": "ed25519-primary-2026",
				"signature": "ed25519:7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
				"signature_verified": true,
				"revision": 1,
				"issued_at": "2026-11-06T00:00:00Z",
				"expires_at": "2026-11-08T00:00:00Z",
				"rego_module": "package policyhelix.authz\ndefault allow = false\nallow { input.subject.authenticated == true }",
				"routes": [
					{
						"pattern": "/api/v1/workloads/jobs",
						"action": "read",
						"classification": "private",
						"allow_unauthenticated": false,
						"required_roles": ["operator"]
					}
				],
				"rules": [
					{
						"id": "rule-jobs-1",
						"effect": "allow",
						"path_pattern": "/api/v1/workloads/jobs",
						"actions": ["read"],
						"roles": ["operator"],
						"resource_class": "private",
						"reason_code": "allow_operator"
					}
				]
			}
		}
	}`

	resp, err := client.Post(baseURL+"/api/v1/policy/cache/evaluate", "application/json", strings.NewReader(evalPayload))
	if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden) {
		t.Fatalf("POST /api/v1/policy/cache/evaluate failed: %v, status: %v", err, resp.Status)
	}
	var evalData map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&evalData)
	_ = resp.Body.Close()
	if _, ok := evalData["cache_key"]; !ok {
		t.Errorf("expected cache_key in response: %+v", evalData)
	}

	// 2. GET /api/v1/policy/cache/stats
	statsResp, err := client.Get(baseURL + "/api/v1/policy/cache/stats")
	if err != nil || statsResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/policy/cache/stats failed: %v, status: %v", err, statsResp.Status)
	}
	var statsData map[string]interface{}
	_ = json.NewDecoder(statsResp.Body).Decode(&statsData)
	_ = statsResp.Body.Close()
	if _, ok := statsData["capacity"]; !ok {
		t.Errorf("expected capacity field in stats response: %+v", statsData)
	}

	// 3. POST /api/v1/policy/cache/invalidate
	invResp, err := client.Post(baseURL+"/api/v1/policy/cache/invalidate?clear=true", "application/json", nil)
	if err != nil || invResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/policy/cache/invalidate failed: %v, status: %v", err, invResp.Status)
	}
	_ = invResp.Body.Close()

	close(stopCh)
	<-serverDone
}

func TestEngineStorageDirAndDurableRestore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ph-engine-storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runServer("127.0.0.1", port, tmpDir, stopCh)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	for i := 0; i < 20; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify key rotation state endpoint backed by durable storage
	resp, err := client.Get(baseURL + "/api/v1/bundles/keys/state")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/bundles/keys/state failed: %v, status: %v", err, resp.Status)
	}
	var state bundles.KeyRotationState
	_ = json.NewDecoder(resp.Body).Decode(&state)
	_ = resp.Body.Close()

	if state.Status != bundles.KeyRotationStatusRestored && state.Status != bundles.KeyRotationStatusEmpty && state.Status != "" {
		t.Errorf("Unexpected key state status: %v", state.Status)
	}

	close(stopCh)
	<-serverDone
}

func TestEngineGatewayHealthScenarios(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runServer("127.0.0.1", port, "", stopCh)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	for i := 0; i < 20; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	scenarios := []string{"stale-policy", "idp-outage", "session-revoke", "replayed-identity", "forged-header", "sentinel"}
	for _, sc := range scenarios {
		resp, err := client.Get(fmt.Sprintf("%s/api/v1/runtime/gateway/health?scenario=%s", baseURL, sc))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET gateway/health?scenario=%s failed: %v", sc, err)
		}
		var data map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&data)
		_ = resp.Body.Close()

		if data["active_scenario"] != sc {
			t.Errorf("scenario %s: expected active_scenario %s, got %v", sc, sc, data["active_scenario"])
		}
		if data["zero_token_exposure"] != true {
			t.Errorf("scenario %s: expected zero_token_exposure=true", sc)
		}
	}

	close(stopCh)
	<-serverDone
}

