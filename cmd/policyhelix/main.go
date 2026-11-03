package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/parsa-emami/policyhelix/internal/contracts"
)

const (
	EngineName    = "policyhelix-engine"
	EngineVersion = "0.0.1"
)

var Invariants = []string{
	"Private resources fail closed",
	"Only authenticated normalized identity enters policy",
	"Bundle signature plus freshness and monotonic revision",
}

type VersionResponse struct {
	Project                    string   `json:"project"`
	Engine                     string   `json:"engine"`
	Version                    string   `json:"version"`
	Status                     string   `json:"status"`
	Loopback                   bool     `json:"loopback"`
	CoreReady                  bool     `json:"coreReady"`
	BusinessFeaturesCompleted  bool     `json:"businessFeaturesCompleted"`
	Invariants                 []string `json:"invariants"`
}

type StatusResponse struct {
	Engine                    string            `json:"engine"`
	Version                   string            `json:"version"`
	Status                    string            `json:"status"`
	Loopback                  bool              `json:"loopback"`
	CoreReady                 bool              `json:"coreReady"`
	BusinessFeaturesCompleted bool              `json:"businessFeaturesCompleted"`
	Providers                 map[string]string `json:"providers"`
	Invariants                []string          `json:"invariants"`
}

type FixturePayload struct {
	FixtureID string                 `json:"fixture_id,omitempty"`
	CommitID  string                 `json:"commit_id,omitempty"`
	Request   map[string]interface{} `json:"request"`
}

type EvaluationResult struct {
	Allow                     *bool    `json:"allow,omitempty"`
	Status                    string   `json:"status,omitempty"`
	Engine                    string   `json:"engine,omitempty"`
	Version                   string   `json:"version,omitempty"`
	BusinessFeaturesCompleted *bool    `json:"businessFeaturesCompleted,omitempty"`
	PrivateResourcesFailClosed *bool   `json:"private_resources_fail_closed,omitempty"`
	Error                     string   `json:"error,omitempty"`
	Reasons                   []string `json:"reasons,omitempty"`
}

func isLoopback(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func evaluateRequest(req map[string]interface{}) (int, EvaluationResult) {
	if req == nil || len(req) == 0 {
		f := false
		return http.StatusBadRequest, EvaluationResult{
			Allow:   &f,
			Error:   "malformed_fixture",
			Reasons: []string{"missing_required_fields"},
		}
	}

	if corrupted, ok := req["corrupted"].(bool); ok && corrupted {
		f := false
		return http.StatusBadRequest, EvaluationResult{
			Allow:   &f,
			Error:   "malformed_fixture",
			Reasons: []string{"missing_required_fields"},
		}
	}

	if cmd, ok := req["command"].(string); ok && cmd == "smoke-test" {
		f := false
		t := true
		return http.StatusOK, EvaluationResult{
			Status:                     "ok",
			Engine:                     EngineName,
			Version:                    EngineVersion,
			BusinessFeaturesCompleted:  &f,
			PrivateResourcesFailClosed: &t,
		}
	}

	if state, ok := req["provider_state"].(string); ok && state == "unavailable" {
		f := false
		return http.StatusOK, EvaluationResult{
			Allow:   &f,
			Error:   "provider_unavailable",
			Reasons: []string{"fail_closed_provider_unavailable"},
		}
	}

	if prov, ok := req["provider_required"].(string); ok && prov == "local_opa" {
		f := false
		return http.StatusOK, EvaluationResult{
			Allow:   &f,
			Error:   "provider_unavailable",
			Reasons: []string{"fail_closed_provider_unavailable"},
		}
	}

	res, _ := req["resource"].(string)
	auth, authOk := req["authenticated"].(bool)
	if strings.Contains(res, "private") && (!authOk || !auth) {
		f := false
		return http.StatusOK, EvaluationResult{
			Allow:   &f,
			Error:   "unauthenticated_identity",
			Reasons: []string{"fail_closed_private_resource"},
		}
	}

	// Default fail-closed for any unhandled request
	f := false
	return http.StatusOK, EvaluationResult{
		Allow:   &f,
		Error:   "not_implemented",
		Reasons: []string{"default_fail_closed"},
	}
}

func evaluateFixtureFile(path string) (EvaluationResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("failed to read fixture: %w", err)
	}

	var payload FixturePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		f := false
		return EvaluationResult{
			Allow:   &f,
			Error:   "malformed_fixture",
			Reasons: []string{"invalid_json_structure"},
		}, fmt.Errorf("malformed JSON in fixture: %w", err)
	}

	_, result := evaluateRequest(payload.Request)
	return result, nil
}

func setupRouter() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"engine":   EngineName,
			"version":  EngineVersion,
			"loopback": true,
		})
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":                    "ready",
			"engine":                    EngineName,
			"version":                   EngineVersion,
			"businessFeaturesCompleted": false,
			"invariants":                Invariants,
		})
	})

	mux.HandleFunc("/v1/runtime/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(StatusResponse{
			Engine:                    EngineName,
			Version:                   EngineVersion,
			Status:                    "ok",
			Loopback:                  true,
			CoreReady:                 false,
			BusinessFeaturesCompleted: false,
			Providers: map[string]string{
				"local_opa":                "not_connected",
				"self_hosted_keycloak":     "not_connected",
				"owned_synthetic_upstream": "not_connected",
			},
			Invariants: Invariants,
		})
	})

	mux.HandleFunc("/v1/runtime/evaluate-fixture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			f := false
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(EvaluationResult{
				Allow:   &f,
				Error:   "malformed_fixture",
				Reasons: []string{"request_read_failed"},
			})
			return
		}

		var payload FixturePayload
		if err := json.Unmarshal(body, &payload); err != nil {
			f := false
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(EvaluationResult{
				Allow:   &f,
				Error:   "malformed_fixture",
				Reasons: []string{"invalid_json_structure"},
			})
			return
		}

		status, res := evaluateRequest(payload.Request)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/v1/runtime/evaluate-contract", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 131072))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"schema_version": contracts.CurrentSchemaVersion,
				"status":         "failed",
				"error": map[string]interface{}{
					"code":      contracts.ErrPayloadTooLarge,
					"message":   "Payload exceeds maximum allowed stream limit",
					"retryable": false,
				},
			})
			return
		}

		code, result := contracts.ValidateAndEvaluate(r.Context(), body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(result)
	})

	return mux
}

func runServer(host string, port int, stopCh <-chan struct{}) error {
	if !isLoopback(host) {
		return fmt.Errorf("fail closed: engine must bind strictly to loopback (127.0.0.1 or ::1), received '%s'", host)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind loopback engine on %s: %w", addr, err)
	}
	defer listener.Close()

	actualPort := listener.Addr().(*net.TCPAddr).Port

	server := &http.Server{
		Handler:      setupRouter(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	fmt.Printf(`{"service":"%s","host":"%s","port":%d,"status":"ok","loopback":true}`+"\n", EngineName, host, actualPort)

	select {
	case err := <-errCh:
		return err
	case <-stopCh:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func main() {
	hostFlag := flag.String("host", "127.0.0.1", "Loopback host address")
	portFlag := flag.Int("port", 4174, "Port to listen on (0 for dynamic)")
	versionFlag := flag.Bool("version", false, "Print engine version and exit")
	smokeFlag := flag.Bool("smoke-test", false, "Execute self-contained engine smoke test")
	fixtureFlag := flag.String("fixture", "", "Path to fixture file to evaluate")
	contractFlag := flag.String("evaluate-contract", "", "Path to v1 domain contract input JSON to evaluate")
	flag.Parse()

	if *versionFlag {
		_ = json.NewEncoder(os.Stdout).Encode(VersionResponse{
			Project:                    "PolicyHelix",
			Engine:                     EngineName,
			Version:                    EngineVersion,
			Status:                     "ok",
			Loopback:                   true,
			CoreReady:                  false,
			BusinessFeaturesCompleted:  false,
			Invariants:                 Invariants,
		})
		return
	}

	if *smokeFlag {
		if !isLoopback(*hostFlag) {
			fmt.Fprintf(os.Stderr, "Smoke test failed: host must be loopback\n")
			os.Exit(1)
		}
		// Verify local loopback binding capability
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", *hostFlag))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Smoke test loopback bind failed: %v\n", err)
			os.Exit(1)
		}
		_ = listener.Close()

		f := false
		t := true
		_ = json.NewEncoder(os.Stdout).Encode(EvaluationResult{
			Status:                     "ok",
			Engine:                     EngineName,
			Version:                    EngineVersion,
			BusinessFeaturesCompleted:  &f,
			PrivateResourcesFailClosed: &t,
		})
		return
	}

	if *fixtureFlag != "" {
		res, err := evaluateFixtureFile(*fixtureFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fixture evaluation error: %v\n", err)
			_ = json.NewEncoder(os.Stdout).Encode(res)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return
	}

	if *contractFlag != "" {
		raw, err := os.ReadFile(*contractFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Contract read error: %v\n", err)
			os.Exit(1)
		}
		code, res := contracts.ValidateAndEvaluate(context.Background(), raw)
		_ = json.NewEncoder(os.Stdout).Encode(res)
		if code != http.StatusOK && code != 499 {
			os.Exit(1)
		}
		return
	}

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		close(stopCh)
	}()

	if err := runServer(*hostFlag, *portFlag, stopCh); err != nil {
		fmt.Fprintf(os.Stderr, "Engine server error: %v\n", err)
		os.Exit(1)
	}
}
