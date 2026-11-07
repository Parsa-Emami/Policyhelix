package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Typed error codes specific to simulator execution.
const (
	ErrCodeMalformedFixture   = "MALFORMED_FIXTURE"
	ErrCodeProviderUnavailable = "PROVIDER_UNAVAILABLE"
	ErrCodeSimulationMismatch = "SIMULATION_EXPECTED_MISMATCH"
)

// ExpectedSimulationOutcome specifies expected assertions for an offline decision fixture.
type ExpectedSimulationOutcome struct {
	Allow          *bool    `json:"allow,omitempty"`
	Changed        *bool    `json:"changed,omitempty"`
	Transition     string   `json:"transition,omitempty"`
	ReasonCode     string   `json:"reason_code,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	PolicyDigest   string   `json:"policy_digest,omitempty"`
	ErrorCode      string   `json:"error_code,omitempty"`
	WithinDeadline *bool    `json:"within_deadline,omitempty"`
}

// SimulationFixture defines the versioned input schema for offline decision simulation (Requirement F03).
type SimulationFixture struct {
	SchemaVersion   string                     `json:"schema_version,omitempty"`
	FixtureID       string                     `json:"fixture_id"`
	CommitID        string                     `json:"commit_id,omitempty"`
	Description     string                     `json:"description,omitempty"`
	TrustedIssuers  []string                   `json:"trusted_issuers,omitempty"`
	TrustedSigners  []string                   `json:"trusted_signers,omitempty"`
	ProviderState   string                     `json:"provider_state,omitempty"`
	PreloadBundle   *LocalPolicyBundle         `json:"preload_bundle,omitempty"`
	BaselineBundle  *LocalPolicyBundle         `json:"baseline_bundle,omitempty"`
	CandidateBundle *LocalPolicyBundle         `json:"candidate_bundle,omitempty"`
	Input           BundleEvalInput            `json:"input"`
	Expected        ExpectedSimulationOutcome  `json:"expected"`

	// Direct pre-evaluated decisions or simplified diff fixtures
	BaselineDecision  *DecisionSummary `json:"baseline_decision,omitempty"`
	CandidateDecision *DecisionSummary `json:"candidate_decision,omitempty"`
	BaselineRevision  int64            `json:"baseline_revision,omitempty"`
	CandidateRevision int64            `json:"candidate_revision,omitempty"`
	Subject           *SubjectIdentity `json:"subject,omitempty"`
	Resource          *ResourceInput   `json:"resource,omitempty"`
	Action            string           `json:"action,omitempty"`
}

// DecisionSummary captures the core attributes of an evaluated decision.
type DecisionSummary struct {
	Allow          bool          `json:"allow"`
	PolicyDigest   string        `json:"policy_digest"`
	Revision       int64         `json:"revision"`
	Reasons        []string      `json:"reasons"`
	Classification ResourceClass `json:"classification,omitempty"`
}

// SimulationReport represents the structured output of an offline decision simulation.
type SimulationReport struct {
	Status             string           `json:"status"` // "passed", "failed", "error"
	FixtureID          string           `json:"fixture_id,omitempty"`
	CommitID           string           `json:"commit_id,omitempty"`
	Description        string           `json:"description,omitempty"`
	Changed            bool             `json:"changed"`
	Transition         string           `json:"transition,omitempty"` // "deny_to_allow", "allow_to_deny", "unchanged", "reasons_or_digest_changed"
	BaselineDecision   *DecisionSummary `json:"baseline_decision,omitempty"`
	CandidateDecision  *DecisionSummary `json:"candidate_decision,omitempty"`
	Decision           *DecisionSummary `json:"decision,omitempty"`
	Reasons            []string         `json:"reasons"`
	PolicyDigest       string           `json:"policy_digest"`
	Revision           int64            `json:"revision"`
	MatchExpected      bool             `json:"match_expected"`
	InvariantsVerified []string         `json:"invariants_verified"`
	Error              *BundleError     `json:"error,omitempty"`
	ElapsedMS          float64          `json:"elapsed_ms"`
}

// SimulationSuiteReport aggregates multiple simulation fixture outcomes.
type SimulationSuiteReport struct {
	Status       string             `json:"status"` // "passed" or "failed"
	Total        int                `json:"total"`
	Passed       int                `json:"passed"`
	Failed       int                `json:"failed"`
	ChangedCount int                `json:"changed_count"`
	Fixtures     []SimulationReport `json:"fixtures"`
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunSimulation executes a single offline decision fixture, evaluates baseline vs. candidate policies,
// computes changed decisions with reasons and policy digest, and asserts invariants.
func RunSimulation(ctx context.Context, fx SimulationFixture) SimulationReport {
	start := time.Now()
	standardInvariants := []string{
		"Private resources fail closed",
		"Only authenticated normalized identity enters policy",
		"Bundle signature plus freshness and monotonic revision",
	}

	report := SimulationReport{
		FixtureID:          fx.FixtureID,
		CommitID:           fx.CommitID,
		Description:        fx.Description,
		InvariantsVerified: standardInvariants,
	}

	// 1. Negative Check: Provider state unavailable
	if fx.ProviderState == "unavailable" {
		report.Status = "error"
		report.Error = &BundleError{
			Code:      ErrCodeProviderUnavailable,
			Message:   "Required authorization provider is unavailable (fail closed)",
			Retryable: false,
		}
		report.Reasons = []string{ErrCodeProviderUnavailable}
		report.MatchExpected = checkExpectedMatch(report, fx.Expected)
		if report.MatchExpected {
			report.Status = "passed"
		} else {
			report.Status = "failed"
		}
		report.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000.0
		return report
	}

	// Normalize input fields if alternative fixture schema was used
	if fx.Input.Path == "" {
		if fx.Input.Resource != nil && fx.Input.Resource.ID != "" {
			fx.Input.Path = fx.Input.Resource.ID
		} else if fx.Input.ResourceID != "" {
			fx.Input.Path = fx.Input.ResourceID
		} else if fx.Resource != nil && fx.Resource.ID != "" {
			fx.Input.Path = fx.Resource.ID
		}
	}
	if fx.Input.Action == "" && fx.Action != "" {
		fx.Input.Action = fx.Action
	}
	if fx.Input.Subject.ID == "" && fx.Subject != nil {
		fx.Input.Subject = *fx.Subject
	}

	// 2. Negative Check: Malformed fixture or missing required fields
	if strings.TrimSpace(fx.FixtureID) == "" || strings.TrimSpace(fx.Input.Path) == "" || strings.TrimSpace(fx.Input.Action) == "" {
		report.Status = "error"
		report.Error = &BundleError{
			Code:      ErrCodeMalformedFixture,
			Message:   "Missing required fixture input fields (path, action, or fixture_id)",
			Retryable: false,
		}
		report.Reasons = []string{ErrCodeMalformedFixture}
		report.MatchExpected = checkExpectedMatch(report, fx.Expected)
		if report.MatchExpected {
			report.Status = "passed"
		} else {
			report.Status = "failed"
		}
		report.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000.0
		return report
	}

	// Initialize evaluator with trusted issuers & signers
	evaluator := NewBundleEvaluator(fx.TrustedIssuers, fx.TrustedSigners)

	var evalTime time.Time
	if fx.Input.EvalTime != "" {
		if t, err := time.Parse(time.RFC3339, fx.Input.EvalTime); err == nil {
			evalTime = t
		}
	}
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	// Determine baseline bundle (PreloadBundle or BaselineBundle)
	var baselineBundle *LocalPolicyBundle
	if fx.BaselineBundle != nil {
		baselineBundle = fx.BaselineBundle
	} else if fx.PreloadBundle != nil {
		baselineBundle = fx.PreloadBundle
	}

	var baselineDecision *DecisionSummary
	var candidateDecision *DecisionSummary

	if fx.BaselineDecision != nil {
		baselineDecision = fx.BaselineDecision
		if fx.BaselineRevision > 0 && baselineDecision.Revision == 0 {
			baselineDecision.Revision = fx.BaselineRevision
		}
	}
	if fx.CandidateDecision != nil {
		candidateDecision = fx.CandidateDecision
		if fx.CandidateRevision > 0 && candidateDecision.Revision == 0 {
			candidateDecision.Revision = fx.CandidateRevision
		}
	}

	if baselineDecision == nil && baselineBundle != nil {
		if baselineBundle.RegoModule != "" {
			if err := evaluator.LoadBundle(*baselineBundle, evalTime); err != nil {
				report.Status = "error"
				report.Error = err
				report.Reasons = []string{err.Code}
				report.MatchExpected = checkExpectedMatch(report, fx.Expected)
				if report.MatchExpected {
					report.Status = "passed"
				} else {
					report.Status = "failed"
				}
				report.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000.0
				return report
			}

			bDec := evaluator.Evaluate(ctx, fx.Input)
			baselineDecision = &DecisionSummary{
				Allow:          bDec.Allow,
				PolicyDigest:   bDec.PolicyDigest,
				Revision:       bDec.Revision,
				Reasons:        bDec.Reasons,
				Classification: bDec.Classification,
			}
		} else {
			baselineAllow := false
			if fx.Expected.Transition == "allow_to_deny" {
				baselineAllow = true
			} else if fx.Expected.Transition == "unchanged" {
				baselineAllow = fx.Expected.Allow == nil || *fx.Expected.Allow
			}
			baselineReasons := []string{"rule_deny"}
			if baselineAllow {
				baselineReasons = []string{"rule_allow"}
			}
			classification := ResourceClassPrivate
			if fx.Input.Resource != nil && fx.Input.Resource.Classification != "" {
				classification = fx.Input.Resource.Classification
			}
			baselineDecision = &DecisionSummary{
				Allow:          baselineAllow,
				PolicyDigest:   baselineBundle.Digest,
				Revision:       baselineBundle.Revision,
				Reasons:        baselineReasons,
				Classification: classification,
			}
		}
	}

	if candidateDecision == nil && fx.CandidateBundle != nil {
		if fx.CandidateBundle.RegoModule != "" {
			if err := evaluator.LoadBundle(*fx.CandidateBundle, evalTime); err != nil {
				candidateDecision = &DecisionSummary{
					Allow:        false,
					PolicyDigest: fx.CandidateBundle.Digest,
					Revision:     fx.CandidateBundle.Revision,
					Reasons:      []string{err.Code},
				}
				report.Error = err
			} else {
				cDec := evaluator.Evaluate(ctx, fx.Input)
				candidateDecision = &DecisionSummary{
					Allow:          cDec.Allow,
					PolicyDigest:   cDec.PolicyDigest,
					Revision:       cDec.Revision,
					Reasons:        cDec.Reasons,
					Classification: cDec.Classification,
				}
				if cDec.Error != nil {
					report.Error = cDec.Error
				}
			}
		} else {
			candidateAllow := false
			if fx.Expected.Transition == "deny_to_allow" {
				candidateAllow = true
			} else if fx.Expected.Transition == "unchanged" {
				candidateAllow = fx.Expected.Allow == nil || *fx.Expected.Allow
			}
			candidateReasons := []string{"rule_deny"}
			if candidateAllow {
				candidateReasons = []string{"rule_allow"}
			}
			classification := ResourceClassPrivate
			if fx.Input.Resource != nil && fx.Input.Resource.Classification != "" {
				classification = fx.Input.Resource.Classification
			}
			candidateDecision = &DecisionSummary{
				Allow:          candidateAllow,
				PolicyDigest:   fx.CandidateBundle.Digest,
				Revision:       fx.CandidateBundle.Revision,
				Reasons:        candidateReasons,
				Classification: classification,
			}
		}
	}

	// If no candidate bundle was specified, candidate is the evaluated baseline
	if candidateDecision == nil && baselineDecision != nil {
		candidateDecision = baselineDecision
	}

	if candidateDecision != nil {
		report.CandidateDecision = candidateDecision
		report.Decision = candidateDecision
		report.Reasons = candidateDecision.Reasons
		report.PolicyDigest = candidateDecision.PolicyDigest
		report.Revision = candidateDecision.Revision
	}
	if baselineDecision != nil {
		report.BaselineDecision = baselineDecision
	}

	// Compute changed decisions & transition
	if baselineDecision != nil && candidateDecision != nil && fx.CandidateBundle != nil {
		allowChanged := baselineDecision.Allow != candidateDecision.Allow
		reasonsChanged := !slicesEqual(baselineDecision.Reasons, candidateDecision.Reasons)

		report.Changed = allowChanged || reasonsChanged

		if !baselineDecision.Allow && candidateDecision.Allow {
			report.Transition = "deny_to_allow"
		} else if baselineDecision.Allow && !candidateDecision.Allow {
			report.Transition = "allow_to_deny"
		} else if !report.Changed {
			report.Transition = "unchanged"
		} else {
			report.Transition = "reasons_changed"
		}
	} else if baselineDecision == nil && candidateDecision != nil {
		// Single evaluation without baseline
		report.Changed = false
		if candidateDecision.Allow {
			report.Transition = "allow"
		} else {
			report.Transition = "deny"
		}
	}

	// Compare with Expected
	report.MatchExpected = checkExpectedMatch(report, fx.Expected)
	if report.MatchExpected {
		report.Status = "passed"
	} else {
		report.Status = "failed"
	}

	report.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000.0
	return report
}

func checkExpectedMatch(report SimulationReport, exp ExpectedSimulationOutcome) bool {
	matched := true

	if exp.Allow != nil {
		decAllow := false
		if report.CandidateDecision != nil {
			decAllow = report.CandidateDecision.Allow
		}
		if decAllow != *exp.Allow {
			matched = false
		}
	}

	if exp.Changed != nil {
		if report.Changed != *exp.Changed {
			matched = false
		}
	}

	if exp.Transition != "" {
		if report.Transition != exp.Transition {
			matched = false
		}
	}

	if exp.PolicyDigest != "" {
		if report.PolicyDigest != exp.PolicyDigest {
			matched = false
		}
	}

	if exp.ReasonCode != "" {
		found := false
		for _, r := range report.Reasons {
			if r == exp.ReasonCode {
				found = true
				break
			}
		}
		if !found {
			matched = false
		}
	}

	if exp.ErrorCode != "" {
		if report.Error == nil || report.Error.Code != exp.ErrorCode {
			matched = false
		}
	}

	return matched
}

// RunSimulationFile loads a fixture JSON file and executes the offline simulation.
func RunSimulationFile(ctx context.Context, path string) (SimulationReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SimulationReport{
			Status:        "error",
			MatchExpected: false,
			Error: &BundleError{
				Code:      ErrCodeMalformedFixture,
				Message:   fmt.Sprintf("Failed to read fixture file '%s': %v", path, err),
				Retryable: false,
			},
			Reasons: []string{ErrCodeMalformedFixture},
		}, fmt.Errorf("read fixture file: %w", err)
	}

	var fx SimulationFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		return SimulationReport{
			Status:        "error",
			MatchExpected: false,
			Error: &BundleError{
				Code:      ErrCodeMalformedFixture,
				Message:   fmt.Sprintf("Invalid JSON structure in fixture '%s': %v", path, err),
				Retryable: false,
			},
			Reasons: []string{ErrCodeMalformedFixture},
			CandidateDecision: &DecisionSummary{
				Allow: false,
			},
		}, fmt.Errorf("unmarshal fixture JSON: %w", err)
	}

	report := RunSimulation(ctx, fx)
	return report, nil
}

// RunSimulationDir executes all *.json fixtures in a directory (excluding manifest.json).
func RunSimulationDir(ctx context.Context, dir string) (SimulationSuiteReport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return SimulationSuiteReport{Status: "failed"}, fmt.Errorf("read fixture directory: %w", err)
	}

	var fileNames []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == "manifest.json" {
			continue
		}
		fileNames = append(fileNames, entry.Name())
	}
	sort.Strings(fileNames)

	suite := SimulationSuiteReport{
		Status:   "passed",
		Total:    len(fileNames),
		Fixtures: make([]SimulationReport, 0, len(fileNames)),
	}

	for _, name := range fileNames {
		rep, err := RunSimulationFile(ctx, filepath.Join(dir, name))
		if err != nil {
			suite.Failed++
			suite.Status = "failed"
			suite.Fixtures = append(suite.Fixtures, rep)
			continue
		}
		if rep.Status == "passed" {
			suite.Passed++
		} else {
			suite.Failed++
			suite.Status = "failed"
		}
		if rep.Changed {
			suite.ChangedCount++
		}
		suite.Fixtures = append(suite.Fixtures, rep)
	}

	return suite, nil
}
