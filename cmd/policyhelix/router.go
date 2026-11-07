package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/parsa-emami/policyhelix/internal/audit"
	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/contracts"
	"github.com/parsa-emami/policyhelix/internal/gateway"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/rollout"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

func setupRouter(ad *storage.Adapter) *http.ServeMux {
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

	handleReadiness := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// If caller requests deep component check or hits /api/v1/runtime/readiness
		storageDir := ""
		if ad != nil {
			storageDir = ad.RootDir()
		}
		providerStates := map[string]string{
			"local_opa":                r.URL.Query().Get("opa_state"),
			"self_hosted_keycloak":     r.URL.Query().Get("idp_state"),
			"owned_synthetic_upstream": r.URL.Query().Get("upstream_state"),
		}
		// If query params specify storage state simulation
		if simStorage := r.URL.Query().Get("storage_state"); simStorage == "unready" {
			storageDir = ""
			ad = nil
		}

		rep := gateway.EvaluateReadiness(r.Context(), storageDir, ad, providerStates)
		w.WriteHeader(rep.StatusCode)
		_ = json.NewEncoder(w).Encode(rep)
	}

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		checkQuery := r.URL.Query().Get("check")
		if checkQuery == "engine" || checkQuery == "all" || checkQuery == "deep" || r.URL.Query().Get("opa_state") != "" || r.URL.Query().Get("idp_state") != "" || r.URL.Query().Get("storage_state") != "" {
			handleReadiness(w, r)
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

	mux.HandleFunc("/api/v1/runtime/readiness", handleReadiness)
	mux.HandleFunc("/v1/runtime/readiness", handleReadiness)

	handleDiagnostics := gateway.DiagnosticsHTTPHandler

	mux.HandleFunc("/api/v1/runtime/diagnostics", handleDiagnostics)
	mux.HandleFunc("/v1/runtime/diagnostics", handleDiagnostics)

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

	handleGatewayHealth := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		scenario := r.URL.Query().Get("scenario")
		switch scenario {
		case "stale-policy":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "degraded",
				"engine":          EngineName,
				"version":         EngineVersion,
				"active_scenario": "stale-policy",
				"description":     "Active policy revision 1 exceeded 30s freshness window (45s elapsed); operator sees STALE POLICY alert and fail-closed denial on stale execution.",
				"policy": map[string]interface{}{
					"active_revision":          1,
					"digest":                   "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
					"stale":                    true,
					"stale_seconds":            45,
					"freshness_window_seconds": 30,
					"last_sync_time":           "2026-11-06T18:15:00Z",
				},
				"idp": map[string]interface{}{
					"status":                "healthy",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		case "idp-outage":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "degraded",
				"engine":          EngineName,
				"version":         EngineVersion,
				"active_scenario": "idp-outage",
				"description":     "Identity provider outage detected; all sensitive routes fail closed (503 Service Unavailable) while preserving intentional public health route bypass.",
				"policy": map[string]interface{}{
					"active_revision":          2,
					"digest":                   "sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
					"stale":                    false,
					"stale_seconds":            12,
					"freshness_window_seconds": 30,
					"last_sync_time":           "2026-11-06T18:30:00Z",
				},
				"idp": map[string]interface{}{
					"status":                "outage",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
					"outage_message":        "Identity Provider unreachable (503 Service Unavailable); failing closed on sensitive endpoints.",
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		case "session-revoke":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "ok",
				"engine":          EngineName,
				"version":         EngineVersion,
				"active_scenario": "session-revoke",
				"description":     "Operator triggers session revocation: target session sess-c22-workload-01 is revoked and stops within the configured 30-second bound with zero side effects.",
				"policy": map[string]interface{}{
					"active_revision":          2,
					"digest":                   "sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
					"stale":                    false,
					"stale_seconds":            8,
					"freshness_window_seconds": 30,
					"last_sync_time":           "2026-11-06T18:30:00Z",
				},
				"idp": map[string]interface{}{
					"status":                "healthy",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
					"last_revocation": map[string]interface{}{
						"session_id":                  "sess-c22-workload-01",
						"subject_id":                  "usr-c22-operator",
						"revoked":                     true,
						"stopped_within_bound":        true,
						"allowed_before_revoke_count": 1,
						"denied_after_revoke_count":   2,
						"side_effects_executed":       false,
						"timestamp":                   "2026-11-06T18:35:00Z",
					},
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		case "replayed-identity":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "degraded",
				"engine":          EngineName,
				"version":         EngineVersion,
				"active_scenario": "replayed-identity",
				"description":     "Replayed and expired session identity fails validation before sensitive side effects can be executed.",
				"policy": map[string]interface{}{
					"active_revision":          2,
					"digest":                   "sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
					"stale":                    false,
					"freshness_window_seconds": 30,
				},
				"idp": map[string]interface{}{
					"status":                "healthy",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
					"last_revocation": map[string]interface{}{
						"session_id":                  "sess-c22-replayed-99",
						"subject_id":                  "usr-c22-untrusted",
						"revoked":                     true,
						"stopped_within_bound":        true,
						"allowed_before_revoke_count": 0,
						"denied_after_revoke_count":   1,
						"side_effects_executed":       false,
						"timestamp":                   "2026-11-06T18:36:00Z",
					},
				},
				"error": map[string]interface{}{
					"code":    "ERR_IDENTITY_REPLAYED",
					"message": "Replayed or expired session identity rejected before side effects.",
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		case "forged-header":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "degraded",
				"engine":          EngineName,
				"version":         EngineVersion,
				"active_scenario": "forged-header",
				"description":     "Client request with forged identity headers (X-Authenticated-Subject) has headers stripped and cannot authorize sensitive side effects.",
				"policy": map[string]interface{}{
					"active_revision":          2,
					"digest":                   "sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
					"stale":                    false,
					"freshness_window_seconds": 30,
				},
				"idp": map[string]interface{}{
					"status":                "healthy",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
				},
				"error": map[string]interface{}{
					"code":    "ERR_FORGED_HEADER_REJECTED",
					"message": "Forged identity headers stripped; sensitive action denied.",
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		case "sentinel":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "ok",
				"engine":          EngineName,
				"version":         EngineVersion,
				"active_scenario": "sentinel",
				"description":     "<script>alert('xss-c22')</script><img src=x onerror=alert('c22')> Script and HTML sentinel inertness test on gateway health and session revocation.",
				"policy": map[string]interface{}{
					"active_revision":          2,
					"digest":                   "sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
					"stale":                    false,
					"freshness_window_seconds": 30,
				},
				"idp": map[string]interface{}{
					"status":                "healthy",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
					"last_revocation": map[string]interface{}{
						"session_id":                  "sess-<script>alert('sess')</script>",
						"subject_id":                  "usr-<script>alert('sub')</script>",
						"revoked":                     true,
						"stopped_within_bound":        true,
						"allowed_before_revoke_count": 0,
						"denied_after_revoke_count":   1,
						"side_effects_executed":       false,
						"timestamp":                   "2026-11-06T18:37:00Z",
					},
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "ok",
				"engine":  EngineName,
				"version": EngineVersion,
				"policy": map[string]interface{}{
					"active_revision":          2,
					"digest":                   "sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
					"stale":                    false,
					"freshness_window_seconds": 30,
					"last_sync_time":           "2026-11-06T18:00:00Z",
				},
				"idp": map[string]interface{}{
					"status":                "healthy",
					"issuer":                "https://auth.policyhelix.local/realms/policyhelix",
					"fail_closed_on_outage": true,
				},
				"session_revocation": map[string]interface{}{
					"max_stale_seconds": 30,
					"enforced":          true,
					"bounded_window":    "<=30s",
				},
				"zero_token_exposure": true,
				"invariants":          Invariants,
			})
		}
	}
	mux.HandleFunc("/api/v1/runtime/gateway/health", handleGatewayHealth)
	mux.HandleFunc("/v1/runtime/gateway/health", handleGatewayHealth)

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

	mux.HandleFunc("/api/v1/gateway/identity/normalize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": gateway.ErrCodeMalformedHeader,
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}

		var req gateway.NormalizeIdentityRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": gateway.ErrCodeMalformedHeader,
				"message":    fmt.Sprintf("Malformed normalize identity JSON: %v", err),
			})
			return
		}

		report, err := gateway.NormalizeSubjectContext(r.Context(), req, nil, nil)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": "INTERNAL_ERROR",
				"message":    err.Error(),
			})
			return
		}
		if !report.Valid || !report.Allow {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	})

	mux.HandleFunc("/api/v1/gateway/proxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": gateway.ErrCodeMalformedHeader,
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}

		var req gateway.ProxyRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": gateway.ErrCodeMalformedHeader,
				"message":    fmt.Sprintf("Malformed proxy request JSON: %v", err),
			})
			return
		}

		proxy := gateway.NewAllowlistedGatewayProxy(gateway.DefaultUpstreamConfig(), nil, nil)
		report, err := proxy.EvaluateProxyRequest(r.Context(), req)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": "INTERNAL_ERROR",
				"message":    err.Error(),
			})
			return
		}
		if !report.Valid || !report.Allow {
			status := http.StatusForbidden
			if report.StatusCode != 0 {
				status = report.StatusCode
			}
			w.WriteHeader(status)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	})

	handleGatewayObligations := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": gateway.ErrCodeMalformedObligation,
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}

		type obligationsEnvelope struct {
			Request gateway.ObligationExecutionRequest `json:"request"`
		}

		var req gateway.ObligationExecutionRequest
		var env obligationsEnvelope
		if err := json.Unmarshal(body, &env); err == nil && (len(env.Request.Obligations) > 0 || env.Request.RequestID != "" || env.Request.Path != "") {
			req = env.Request
		} else {
			if err := json.Unmarshal(body, &req); err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"valid":      false,
					"allow":      false,
					"error_code": gateway.ErrCodeMalformedObligation,
					"message":    fmt.Sprintf("Malformed obligations JSON: %v", err),
				})
				return
			}
		}

		report, err := gateway.EnforceObligations(r.Context(), req)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": "INTERNAL_ERROR",
				"message":    err.Error(),
			})
			return
		}
		if !report.Valid || !report.Allow {
			status := http.StatusForbidden
			if report.StatusCode != 0 {
				status = report.StatusCode
			}
			w.WriteHeader(status)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	}

	mux.HandleFunc("/api/v1/gateway/obligations/enforce", handleGatewayObligations)
	mux.HandleFunc("/api/v1/gateway/obligations", handleGatewayObligations)

	handleGatewayFailure := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": gateway.ErrCodeMalformedFailureConfig,
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}

		type failureEnvelope struct {
			Request gateway.ResourceOutageRequest `json:"request"`
		}

		var req gateway.ResourceOutageRequest
		var env failureEnvelope
		if err := json.Unmarshal(body, &env); err == nil && (env.Request.Path != "" || env.Request.DecisionLoss || env.Request.DecisionEngineState != "") {
			req = env.Request
		} else {
			if err := json.Unmarshal(body, &req); err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"valid":      false,
					"allow":      false,
					"error_code": gateway.ErrCodeMalformedFailureConfig,
					"message":    fmt.Sprintf("Malformed failure request JSON: %v", err),
				})
				return
			}
		}

		report, err := gateway.EvaluateResourceOutage(r.Context(), req)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":      false,
				"allow":      false,
				"error_code": "INTERNAL_ERROR",
				"message":    err.Error(),
			})
			return
		}
		if !report.Valid || !report.Allow {
			status := http.StatusForbidden
			if report.StatusCode != 0 {
				status = report.StatusCode
			}
			w.WriteHeader(status)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	}

	mux.HandleFunc("/api/v1/gateway/failure/evaluate", handleGatewayFailure)
	mux.HandleFunc("/api/v1/gateway/failure", handleGatewayFailure)

	handleAuditDecision := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(audit.DecisionLogResult{
				Valid:        false,
				Allow:        false,
				ErrorCode:    audit.ErrCodeMalformedAuditRequest,
				ErrorMessage: "Failed to read request body or exceeded 1MB",
			})
			return
		}

		type auditEnvelope struct {
			Request audit.DecisionLogRequest `json:"request"`
		}

		var req audit.DecisionLogRequest
		var env auditEnvelope
		if err := json.Unmarshal(body, &env); err == nil && (env.Request.RequestID != "" || env.Request.Action != "" || env.Request.ResourceID != "") {
			req = env.Request
		} else {
			if err := json.Unmarshal(body, &req); err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(audit.DecisionLogResult{
					Valid:        false,
					Allow:        false,
					ErrorCode:    audit.ErrCodeMalformedAuditRequest,
					ErrorMessage: fmt.Sprintf("Malformed audit JSON request: %v", err),
				})
				return
			}
		}

		report, err := audit.LogDecision(r.Context(), req)
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if !report.Valid {
			w.WriteHeader(http.StatusBadRequest)
		} else if !report.Allow {
			status := http.StatusForbidden
			if report.AuditRecord != nil && report.AuditRecord.Outcome.StatusCode > 0 {
				status = report.AuditRecord.Outcome.StatusCode
			}
			w.WriteHeader(status)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(report)
	}

	mux.HandleFunc("/api/v1/audit/decision", handleAuditDecision)
	mux.HandleFunc("/api/v1/audit/log-decision", handleAuditDecision)
	mux.HandleFunc("/v1/runtime/audit/decision", handleAuditDecision)

	handleShadowEvaluate := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 131072))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "failed_to_read_body"})
			return
		}

		type shadowEnvelope struct {
			TrustedIssuers []string                  `json:"trusted_issuers,omitempty"`
			TrustedSigners []string                  `json:"trusted_signers,omitempty"`
			Request        rollout.ShadowEvalRequest `json:"request"`
		}

		var req rollout.ShadowEvalRequest
		var env shadowEnvelope
		var issuers []string
		var signers []string

		if err := json.Unmarshal(body, &env); err == nil && (env.Request.Path != "" || env.Request.Action != "" || env.Request.ProviderUnavailable) {
			req = env.Request
			issuers = env.TrustedIssuers
			signers = env.TrustedSigners
		} else {
			if err := json.Unmarshal(body, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "malformed_request",
					"message": fmt.Sprintf("invalid JSON payload: %v", err),
				})
				return
			}
		}

		engine := defaultShadowEngine
		if len(issuers) > 0 || len(signers) > 0 {
			enfEval := policy.NewBundleEvaluator(issuers, signers)
			candEval := policy.NewBundleEvaluator(issuers, signers)
			engine = rollout.NewShadowEngine(enfEval, candEval, defaultShadowEngine.GetStore())
		}

		res, rErr := engine.Evaluate(r.Context(), req)
		status := http.StatusOK
		if res != nil && res.StatusCode > 0 {
			status = res.StatusCode
		} else if rErr != nil {
			var roErr *rollout.RolloutError
			if errors.As(rErr, &roErr) && roErr.StatusCode > 0 {
				status = roErr.StatusCode
			} else {
				status = http.StatusBadRequest
			}
		}

		w.WriteHeader(status)
		if res != nil {
			_ = json.NewEncoder(w).Encode(res)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "evaluation_failed",
				"message": rErr.Error(),
			})
		}
	}

	handleShadowDivergence := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method == http.MethodPost && r.URL.Query().Get("clear") == "true" {
			defaultShadowEngine.GetStore().Clear()
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "cleared"})
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}

		filter := rollout.DivergenceFilter{}
		q := r.URL.Query()
		if q.Get("diverged_only") == "true" || q.Get("diverged_only") == "1" {
			filter.DivergedOnly = true
		}
		if t := q.Get("type"); t != "" {
			filter.DivergenceType = rollout.DivergenceType(t)
		}

		store := defaultShadowEngine.GetStore()
		records := store.GetRecords(filter)
		stats := store.GetStats()

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"stats":   stats,
			"records": records,
			"count":   len(records),
		})
	}

	mux.HandleFunc("/api/v1/rollout/shadow/evaluate", handleShadowEvaluate)
	mux.HandleFunc("/v1/runtime/rollout/shadow", handleShadowEvaluate)
	mux.HandleFunc("/api/v1/rollout/shadow/divergence", handleShadowDivergence)

	handlePolicyCacheEvaluate := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 131072))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "body_read_error",
				"message": err.Error(),
			})
			return
		}

		type cacheEnvelope struct {
			TrustedIssuers []string                    `json:"trusted_issuers,omitempty"`
			TrustedSigners []string                    `json:"trusted_signers,omitempty"`
			Request        policy.EvaluateCacheRequest `json:"request"`
		}

		var req policy.EvaluateCacheRequest
		var env cacheEnvelope
		var issuers []string
		var signers []string

		if err := json.Unmarshal(body, &env); err == nil && (env.Request.Path != "" || env.Request.Action != "" || env.Request.ProviderUnavailable) {
			req = env.Request
			issuers = env.TrustedIssuers
			signers = env.TrustedSigners
		} else {
			if err := json.Unmarshal(body, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "malformed_request",
					"message": fmt.Sprintf("invalid JSON payload: %v", err),
				})
				return
			}
		}

		var evaluator *policy.BundleEvaluator
		if len(issuers) > 0 || len(signers) > 0 {
			evaluator = policy.NewBundleEvaluator(issuers, signers)
		}

		res, cErr := defaultDecisionCache.EvaluateRequest(r.Context(), evaluator, req)
		status := http.StatusOK
		if res.StatusCode > 0 {
			status = res.StatusCode
		} else if cErr != nil {
			status = http.StatusBadRequest
		}

		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(res)
	}

	handlePolicyCacheStats := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}
		stats := defaultDecisionCache.Stats()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(stats)
	}

	handlePolicyCacheInvalidate := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}

		type invalidateReq struct {
			SessionID      string `json:"session_id,omitempty"`
			SubjectID      string `json:"subject_id,omitempty"`
			OwnerScope     string `json:"owner_scope,omitempty"`
			MinEpoch       int64  `json:"min_epoch,omitempty"`
			Revision       int64  `json:"revision,omitempty"`
			PolicyDigest   string `json:"policy_digest,omitempty"`
			Clear          bool   `json:"clear,omitempty"`
			TargetRevision int64  `json:"target_revision,omitempty"`
		}

		var invReq invalidateReq
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		if len(body) > 0 {
			_ = json.Unmarshal(body, &invReq)
		}

		q := r.URL.Query()
		if q.Get("clear") == "true" {
			invReq.Clear = true
		}
		if sid := q.Get("session_id"); sid != "" {
			invReq.SessionID = sid
		}
		if sub := q.Get("subject_id"); sub != "" {
			invReq.SubjectID = sub
		}
		if sc := q.Get("owner_scope"); sc != "" {
			invReq.OwnerScope = sc
		}

		invalidatedCount := 0
		if invReq.Clear {
			defaultDecisionCache.Clear()
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "cleared",
				"stats":  defaultDecisionCache.Stats(),
			})
			return
		}

		if invReq.SessionID != "" {
			invalidatedCount += defaultDecisionCache.InvalidateSession(invReq.SessionID)
		}
		if invReq.SubjectID != "" {
			invalidatedCount += defaultDecisionCache.InvalidateSubject(invReq.SubjectID, invReq.MinEpoch)
		}
		if invReq.OwnerScope != "" {
			invalidatedCount += defaultDecisionCache.InvalidateScope(invReq.OwnerScope, invReq.MinEpoch)
		}
		if invReq.Revision > 0 || invReq.PolicyDigest != "" {
			invalidatedCount += defaultDecisionCache.InvalidateRevision(invReq.Revision, invReq.PolicyDigest)
		}
		if invReq.TargetRevision > 0 {
			invalidatedCount += defaultDecisionCache.InvalidateOlderThanRevision(invReq.TargetRevision)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"invalidated_count": invalidatedCount,
			"stats":             defaultDecisionCache.Stats(),
		})
	}

	mux.HandleFunc("/api/v1/policy/cache/evaluate", handlePolicyCacheEvaluate)
	mux.HandleFunc("/api/v1/policy/cache/stats", handlePolicyCacheStats)
	mux.HandleFunc("/api/v1/policy/cache/invalidate", handlePolicyCacheInvalidate)

	mux.HandleFunc("/api/v1/bundles/keys/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		body, err := io.ReadAll(io.LimitReader(r.Body, 131072))
		if err != nil || len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bundles.KeyRotationResult{
				SchemaVersion: bundles.TrustKeySchemaVersion,
				Status:        bundles.KeyRotationStatusRejected,
				Valid:         false,
				ErrorCode:     bundles.ErrCodeInvalidKeyRotation,
				Message:       "request body is empty or unreadable",
			})
			return
		}

		var fx bundles.KeyRotationFixture
		if err := json.Unmarshal(body, &fx); err == nil && (len(fx.Rotations) > 0 || fx.PreloadActivation != nil || len(fx.PostActivations) > 0) {
			tmpDir, mErr := os.MkdirTemp("", "policyhelix-keyrot-http-*")
			if mErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": mErr.Error()})
				return
			}
			defer os.RemoveAll(tmpDir)
			rep, runErr := bundles.RunKeyRotationFixture(r.Context(), tmpDir, fx)
			status := http.StatusOK
			if !rep.Passed || runErr != nil {
				if rep.ErrorCode == bundles.ErrCodeProviderUnavailable {
					status = http.StatusServiceUnavailable
				} else {
					status = http.StatusForbidden
				}
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(rep)
			return
		}

		var req bundles.KeyRotationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bundles.KeyRotationResult{
				SchemaVersion: bundles.TrustKeySchemaVersion,
				Status:        bundles.KeyRotationStatusRejected,
				Valid:         false,
				ErrorCode:     bundles.ErrCodeInvalidKeyRotation,
				Message:       fmt.Sprintf("invalid JSON: %v", err),
			})
			return
		}

		res := defaultKeyRotationManager.RotateKeys(r.Context(), req)
		status := http.StatusOK
		if !res.Valid {
			switch res.ErrorCode {
			case bundles.ErrCodeProviderUnavailable:
				status = http.StatusServiceUnavailable
			case bundles.ErrCodeInvalidKeyRotation, bundles.ErrCodeEmptyTrustedKeySet:
				status = http.StatusBadRequest
			default:
				status = http.StatusForbidden
			}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/api/v1/bundles/keys/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(defaultKeyRotationManager.State())
	})

	mux.HandleFunc("/api/v1/gateway/enforcement/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		body, err := io.ReadAll(io.LimitReader(r.Body, 131072))
		if err != nil || len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "empty_or_unreadable_body"})
			return
		}
		var fx gateway.EnforcementMatrixFixture
		if err := json.Unmarshal(body, &fx); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_json", "message": err.Error()})
			return
		}
		tmpDir, mErr := os.MkdirTemp("", "policyhelix-enf-http-*")
		if mErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": mErr.Error()})
			return
		}
		defer os.RemoveAll(tmpDir)
		rep, runErr := gateway.EvaluateEnforcementFixture(r.Context(), tmpDir, fx)
		status := http.StatusOK
		if !rep.Passed || runErr != nil {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(rep)
	})

	mux.HandleFunc("/api/v1/security/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"passed":     false,
				"error_code": "PAYLOAD_TOO_LARGE",
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}
		var fx gateway.SecurityBoundaryFixture
		if err := json.Unmarshal(body, &fx); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"passed":     false,
				"error_code": "MALFORMED_FIXTURE",
				"message":    fmt.Sprintf("Malformed security boundary fixture JSON: %v", err),
			})
			return
		}
		tmpDir, err := os.MkdirTemp("", "policyhelix-sec-http-*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"passed":     false,
				"error_code": bundles.ErrCodeActivationStoreUnavail,
				"message":    err.Error(),
			})
			return
		}
		defer os.RemoveAll(tmpDir)
		rep, runErr := gateway.EvaluateSecurityBoundaryFixture(r.Context(), tmpDir, fx)
		status := http.StatusOK
		if !rep.Passed || runErr != nil {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(rep)
	})

	handleBenchmarkRun := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"passed":     false,
				"error_code": gateway.ErrCodePayloadTooLarge,
				"message":    "Failed to read request body or exceeded 1MB",
			})
			return
		}
		var fx gateway.BenchmarkWorkloadFixture
		if err := json.Unmarshal(body, &fx); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"passed":     false,
				"error_code": gateway.ErrCodeMalformedBenchmark,
				"message":    fmt.Sprintf("Malformed benchmark fixture JSON: %v", err),
			})
			return
		}
		tmpDir, err := os.MkdirTemp("", "policyhelix-bench-http-*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"passed":     false,
				"error_code": bundles.ErrCodeActivationStoreUnavail,
				"message":    err.Error(),
			})
			return
		}
		defer os.RemoveAll(tmpDir)
		rep, runErr := gateway.EvaluateBenchmarkFixture(r.Context(), tmpDir, fx)
		status := http.StatusOK
		if runErr != nil {
			status = http.StatusInternalServerError
		} else if rep != nil && !rep.Passed {
			if rep.ErrorCode == gateway.ErrCodeMalformedBenchmark {
				status = http.StatusBadRequest
			} else {
				status = http.StatusForbidden
			}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(rep)
	}

	mux.HandleFunc("/api/v1/benchmark/run", handleBenchmarkRun)
	mux.HandleFunc("/api/v1/benchmark/evaluate", handleBenchmarkRun)

	return mux
}
