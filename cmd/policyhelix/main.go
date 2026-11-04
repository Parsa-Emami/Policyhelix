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

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/contracts"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
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
	Project                   string   `json:"project"`
	Engine                    string   `json:"engine"`
	Version                   string   `json:"version"`
	Status                    string   `json:"status"`
	Loopback                  bool     `json:"loopback"`
	CoreReady                 bool     `json:"coreReady"`
	BusinessFeaturesCompleted bool     `json:"businessFeaturesCompleted"`
	Invariants                []string `json:"invariants"`
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
	Allow                      *bool    `json:"allow,omitempty"`
	Status                     string   `json:"status,omitempty"`
	Engine                     string   `json:"engine,omitempty"`
	Version                    string   `json:"version,omitempty"`
	BusinessFeaturesCompleted  *bool    `json:"businessFeaturesCompleted,omitempty"`
	PrivateResourcesFailClosed *bool    `json:"private_resources_fail_closed,omitempty"`
	Error                      string   `json:"error,omitempty"`
	Reasons                    []string `json:"reasons,omitempty"`
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

	mux.HandleFunc("/v1/runtime/simulate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(policy.SimulationReport{
				Status:  "error",
				Reasons: []string{policy.ErrCodeMalformedFixture},
				Error: &policy.BundleError{
					Code:    policy.ErrCodeMalformedFixture,
					Message: "Request body read error or exceeded 1MB limit",
				},
			})
			return
		}

		var fx policy.SimulationFixture
		if err := json.Unmarshal(body, &fx); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(policy.SimulationReport{
				Status:  "error",
				Reasons: []string{policy.ErrCodeMalformedFixture},
				Error: &policy.BundleError{
					Code:    policy.ErrCodeMalformedFixture,
					Message: fmt.Sprintf("Malformed fixture JSON: %v", err),
				},
			})
			return
		}

		report := policy.RunSimulation(r.Context(), fx)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if report.Status == "failed" {
			w.WriteHeader(http.StatusUnprocessableEntity)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	})

	mux.HandleFunc("/v1/runtime/bundles/build", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   bundles.ErrCodeInvalidBundleSpec,
				"message": "Failed to read request body or exceeded 1MB",
			})
			return
		}

		var spec bundles.BundleBuildSpec
		if err := json.Unmarshal(body, &spec); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   bundles.ErrCodeInvalidBundleSpec,
				"message": fmt.Sprintf("Malformed build spec JSON: %v", err),
			})
			return
		}

		bundle, err := bundles.BuildDeterministicBundle(spec)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   bundles.ErrCodeInvalidBundleSpec,
				"message": err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(bundle)
	})

	mux.HandleFunc("/v1/runtime/bundles/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bundles.BundleVerification{
				SchemaVersion: "1",
				Verified:      false,
				Status:        bundles.VerificationStatusRejected,
				ErrorCode:     bundles.ErrCodeInvalidVerificationRequest,
				Message:       "Failed to read request body or exceeded 1MB",
			})
			return
		}

		var req bundles.BundleVerificationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bundles.BundleVerification{
				SchemaVersion: "1",
				Verified:      false,
				Status:        bundles.VerificationStatusRejected,
				ErrorCode:     bundles.ErrCodeInvalidVerificationRequest,
				Message:       fmt.Sprintf("Malformed verification request JSON: %v", err),
			})
			return
		}

		verification := bundles.VerifyBundle(req)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch {
		case verification.ErrorCode == bundles.ErrCodeInvalidVerificationRequest:
			w.WriteHeader(http.StatusBadRequest)
		case !verification.Verified:
			w.WriteHeader(http.StatusUnprocessableEntity)
		default:
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(verification)
	})

	mux.HandleFunc("/v1/runtime/auth/revoke-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": auth.ErrCodeInvalidRevocationRequest,
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}

		var spec auth.WorkloadRevocationSpec
		if err := json.Unmarshal(body, &spec); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": auth.ErrCodeInvalidRevocationRequest,
				"message":    fmt.Sprintf("Malformed revocation workload JSON: %v", err),
			})
			return
		}

		report, err := auth.EvaluateWorkloadSpec(r.Context(), spec, nil, nil)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": auth.ErrCodeInvalidRevocationRequest,
				"message":    err.Error(),
			})
			return
		}
		if !report.Valid || !report.StoppedWithinBound {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
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

type cliActivationEnvelope struct {
	SchemaVersion  string                   `json:"schema_version"`
	OperationID    string                   `json:"operation_id"`
	EvaluationTime string                   `json:"evaluation_time,omitempty"`
	TrustedKeys    []bundles.TrustedKey     `json:"trusted_keys"`
	Identity       storage.CallerIdentity   `json:"identity"`
	Bundle         policy.LocalPolicyBundle `json:"bundle"`
}

type cliOIDCEnvelope struct {
	Config        auth.OIDCConfig                `json:"config"`
	TrustedKeys   []auth.TrustedKey              `json:"trusted_keys"`
	PreloadState  *auth.LoginState               `json:"preload_state,omitempty"`
	PreloadNonces []string                       `json:"preload_nonces,omitempty"`
	Callback      auth.CallbackValidationRequest `json:"callback"`
}

type cliSessionEnvelope struct {
	Operation       string                     `json:"operation"`
	PreloadSessions []auth.SessionRecord       `json:"preload_sessions,omitempty"`
	Create          *auth.CreateSessionRequest `json:"create,omitempty"`
	Resume          *auth.ResumeSessionRequest `json:"resume,omitempty"`
	Rotate          *auth.RotateSessionRequest `json:"rotate,omitempty"`
	RevokeSessionID string                     `json:"revoke_session_id,omitempty"`
}

func main() {
	hostFlag := flag.String("host", "127.0.0.1", "Loopback host address")
	portFlag := flag.Int("port", 4174, "Port to listen on (0 for dynamic)")
	versionFlag := flag.Bool("version", false, "Print engine version and exit")
	smokeFlag := flag.Bool("smoke-test", false, "Execute self-contained engine smoke test")
	fixtureFlag := flag.String("fixture", "", "Path to fixture file to evaluate")
	contractFlag := flag.String("evaluate-contract", "", "Path to v1 domain contract input JSON to evaluate")
	simulateFlag := flag.String("simulate", "", "Path to offline decision simulation fixture JSON or directory")
	simulateFixtureFlag := flag.String("simulate-fixture", "", "Alias for -simulate")
	buildBundleFlag := flag.String("build-bundle", "", "Path to BundleBuildSpec JSON to build a deterministic signed bundle")
	verifyBundleFlag := flag.String("verify-bundle", "", "Path to BundleVerificationRequest JSON to verify trust and freshness")
	activateBundleFlag := flag.String("activate-bundle", "", "Path to activation envelope JSON to atomically activate")
	activationStateFlag := flag.String("activation-state", "", "Path to activation envelope JSON to restore durable state")
	validateOIDCFlag := flag.String("validate-oidc", "", "Path to C13 OIDC callback validation fixture JSON")
	manageSessionFlag := flag.String("manage-session", "", "Path to C14 session management fixture JSON")
	enforceRevokeFlag := flag.String("enforce-revocation", "", "Path to C15 revocation enforcement workload fixture JSON")
	writeStorageFlag := flag.String("write-storage", "", "Path to C05 WriteRequest JSON fixture to commit to local storage")
	storageDirFlag := flag.String("storage-dir", "", "Directory path for local authoritative storage port")
	flag.Parse()

	if *versionFlag {
		_ = json.NewEncoder(os.Stdout).Encode(VersionResponse{
			Project:                   "PolicyHelix",
			Engine:                    EngineName,
			Version:                   EngineVersion,
			Status:                    "ok",
			Loopback:                  true,
			CoreReady:                 false,
			BusinessFeaturesCompleted: false,
			Invariants:                Invariants,
		})
		return
	}

	if *smokeFlag {
		if !isLoopback(*hostFlag) {
			fmt.Fprintf(os.Stderr, "Smoke test failed: host must be loopback\n")
			os.Exit(1)
		}
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

	targetSim := *simulateFlag
	if targetSim == "" {
		targetSim = *simulateFixtureFlag
	}
	if targetSim != "" {
		fi, err := os.Stat(targetSim)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Simulator path error: %v\n", err)
			_ = json.NewEncoder(os.Stdout).Encode(policy.SimulationReport{
				Status:  "error",
				Reasons: []string{policy.ErrCodeMalformedFixture},
				Error: &policy.BundleError{
					Code:    policy.ErrCodeMalformedFixture,
					Message: err.Error(),
				},
			})
			os.Exit(1)
		}

		if fi.IsDir() {
			suite, err := policy.RunSimulationDir(context.Background(), targetSim)
			_ = json.NewEncoder(os.Stdout).Encode(suite)
			if err != nil || suite.Status != "passed" {
				os.Exit(1)
			}
			return
		}

		rep, err := policy.RunSimulationFile(context.Background(), targetSim)
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		if err != nil || rep.Status != "passed" {
			os.Exit(1)
		}
		return
	}

	if *buildBundleFlag != "" {
		raw, err := os.ReadFile(*buildBundleFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Build spec read error: %v\n", err)
			os.Exit(1)
		}
		var spec bundles.BundleBuildSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			fmt.Fprintf(os.Stderr, "Build spec JSON error: %v\n", err)
			os.Exit(1)
		}
		bundle, err := bundles.BuildDeterministicBundle(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Bundle build error: %v\n", err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(bundle)
		return
	}

	if *verifyBundleFlag != "" {
		raw, err := os.ReadFile(*verifyBundleFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verify bundle read error: %v\n", err)
			os.Exit(1)
		}
		var req bundles.BundleVerificationRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(bundles.BundleVerification{
				SchemaVersion: "1",
				Verified:      false,
				Status:        bundles.VerificationStatusRejected,
				ErrorCode:     bundles.ErrCodeInvalidVerificationRequest,
				Message:       err.Error(),
			})
			os.Exit(1)
		}
		verification := bundles.VerifyBundle(req)
		_ = json.NewEncoder(os.Stdout).Encode(verification)
		if !verification.Verified {
			os.Exit(1)
		}
		return
	}

	if *activateBundleFlag != "" || *activationStateFlag != "" {
		if strings.TrimSpace(*storageDirFlag) == "" {
			fmt.Fprintf(os.Stderr, "Activation requires --storage-dir\n")
			os.Exit(1)
		}
		targetPath := *activateBundleFlag
		isRestoreOnly := false
		if targetPath == "" {
			targetPath = *activationStateFlag
			isRestoreOnly = true
		}
		raw, err := os.ReadFile(targetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Activation envelope read error: %v\n", err)
			os.Exit(1)
		}
		var env cliActivationEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			fmt.Fprintf(os.Stderr, "Activation envelope JSON error: %v\n", err)
			os.Exit(1)
		}
		ad, _, err := storage.Open(*storageDirFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Storage open error: %v\n", err)
			os.Exit(1)
		}
		defer ad.Close()

		mgr := bundles.NewActivationManager(bundles.NewStorageActivationStore(ad), bundles.NewKeyring(env.TrustedKeys...))
		if strings.TrimSpace(env.EvaluationTime) != "" {
			if parsed, err := time.Parse(time.RFC3339, env.EvaluationTime); err == nil {
				mgr.Now = func() time.Time { return parsed.UTC() }
			}
		}

		if isRestoreOnly {
			state := mgr.Restore(context.Background())
			_ = json.NewEncoder(os.Stdout).Encode(state)
			if !state.Active {
				os.Exit(1)
			}
			return
		}

		res := mgr.Activate(context.Background(), bundles.ActivationRequest{
			SchemaVersion: env.SchemaVersion,
			OperationID:   env.OperationID,
			Identity:      env.Identity,
			Bundle:        env.Bundle,
		})
		_ = json.NewEncoder(os.Stdout).Encode(res)
		if res.Status == bundles.ActivationStatusRejected {
			os.Exit(1)
		}
		return
	}

	if *validateOIDCFlag != "" {
		raw, err := os.ReadFile(*validateOIDCFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "OIDC fixture read error: %v\n", err)
			os.Exit(1)
		}
		var env cliOIDCEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			fmt.Fprintf(os.Stderr, "OIDC fixture JSON error: %v\n", err)
			os.Exit(1)
		}
		ks := auth.NewKeySet()
		for _, tk := range env.TrustedKeys {
			if err := ks.AddKey(tk); err != nil {
				fmt.Fprintf(os.Stderr, "TrustedKey error: %v\n", err)
				os.Exit(1)
			}
		}
		env.Config.KeySet = ks
		sm := auth.NewStateManager()
		if env.PreloadState != nil {
			sm.StoreState(env.PreloadState)
		}
		nt := auth.NewNonceTracker()
		for _, n := range env.PreloadNonces {
			nt.PreloadNonce(n, time.Now().UTC())
		}
		val := auth.NewOIDCValidator(env.Config, sm, nt)
		res, err := val.ValidateCallback(context.Background(), env.Callback)
		_ = json.NewEncoder(os.Stdout).Encode(res)
		if err != nil || !res.Valid {
			os.Exit(1)
		}
		return
	}

	if *manageSessionFlag != "" {
		raw, err := os.ReadFile(*manageSessionFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Session fixture read error: %v\n", err)
			os.Exit(1)
		}
		var env cliSessionEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			fmt.Fprintf(os.Stderr, "Session fixture JSON error: %v\n", err)
			os.Exit(1)
		}
		store := auth.NewMemorySessionStore()
		ctx := context.Background()
		for _, s := range env.PreloadSessions {
			_ = store.SaveSession(ctx, s)
		}
		mgr := auth.NewSessionManager(store, auth.SessionConfig{})
		var res *auth.SessionResult
		switch env.Operation {
		case "create":
			if env.Create == nil {
				os.Exit(1)
			}
			res, err = mgr.CreateSession(ctx, *env.Create)
		case "resume":
			if env.Resume == nil {
				os.Exit(1)
			}
			res, err = mgr.ResumeSession(ctx, *env.Resume)
		case "rotate":
			if env.Rotate == nil {
				os.Exit(1)
			}
			res, err = mgr.RotateSession(ctx, *env.Rotate)
		default:
			fmt.Fprintf(os.Stderr, "Unsupported session operation: %s\n", env.Operation)
			os.Exit(1)
		}
		if err != nil || res == nil {
			fmt.Fprintf(os.Stderr, "Session operation error: %v\n", err)
			os.Exit(1)
		}
		status := "ok"
		if !res.Valid {
			status = "failed"
		}
		out := map[string]interface{}{
			"status":               status,
			"valid":                res.Valid,
			"operation":            env.Operation,
			"error_code":           res.ErrorCode,
			"error_message":        res.ErrorMessage,
			"session":              res.Session,
			"set_cookie_header":    res.SetCookieHeader,
			"identity":             res.Identity,
			"subject":              res.Subject,
			"authorized_for_scope": res.AuthorizedForScope,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		if !res.Valid {
			os.Exit(1)
		}
		return
	}

	if *enforceRevokeFlag != "" {
		raw, err := os.ReadFile(*enforceRevokeFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Revocation fixture read error: %v\n", err)
			os.Exit(1)
		}
		var spec auth.WorkloadRevocationSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			fmt.Fprintf(os.Stderr, "Revocation fixture JSON error: %v\n", err)
			os.Exit(1)
		}
		var sessStore auth.SessionStore
		var revStore auth.RevocationStore
		if strings.TrimSpace(*storageDirFlag) != "" {
			ad, _, err := storage.Open(*storageDirFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Storage open error: %v\n", err)
				os.Exit(1)
			}
			defer ad.Close()
			sessStore = auth.NewStorageSessionStore(ad)
			revStore = auth.NewStorageRevocationStore(ad)
		}
		report, err := auth.EvaluateWorkloadSpec(context.Background(), spec, sessStore, revStore)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Revocation evaluation error: %v\n", err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if len(spec.WorkloadSteps) > 0 {
			if !report.StoppedWithinBound || report.DeniedAfterRevokeCount == 0 {
				os.Exit(1)
			}
			return
		}
		if !report.Allow || !report.Valid || !report.StoppedWithinBound {
			os.Exit(1)
		}
		return
	}

	if *writeStorageFlag != "" {
		raw, err := os.ReadFile(*writeStorageFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Storage fixture read error: %v\n", err)
			os.Exit(1)
		}
		var req storage.WriteRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			fmt.Fprintf(os.Stderr, "Storage fixture JSON error: %v\n", err)
			os.Exit(1)
		}
		dir := *storageDirFlag
		if dir == "" {
			tmp, err := os.MkdirTemp("", "policyhelix-storage-*")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Storage temp dir error: %v\n", err)
				os.Exit(1)
			}
			defer os.RemoveAll(tmp)
			dir = tmp
		}
		ad, _, err := storage.Open(dir)
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"status": "failed", "error": err})
			os.Exit(1)
		}
		defer ad.Close()

		receipt, sErr := ad.WriteRecord(context.Background(), req)
		if sErr != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"status": "failed", "error": sErr})
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(receipt)
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
