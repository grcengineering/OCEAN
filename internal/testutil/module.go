package testutil

import (
	"context"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// StubCollector is a configurable fake that satisfies module.Collector.
// Use it when you need a collector in the registry but don't care about
// its behavior (e.g., testing the executor, API handlers, CLI).
type StubCollector struct {
	IDValue           string
	NameValue         string
	VersionValue      string
	SourceSystemValue string
	EvidenceTypeValues []int
	CredReqs          []module.CredentialReq
	CollectFunc       func(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}

// Compile-time interface check.
var _ module.Collector = (*StubCollector)(nil)

// NewStubCollector returns a StubCollector with sensible defaults.
func NewStubCollector(id string) *StubCollector {
	return &StubCollector{
		IDValue:           id,
		NameValue:         "Stub Collector: " + id,
		VersionValue:      "0.1.0",
		SourceSystemValue: "test",
		EvidenceTypeValues: []int{9999},
		CollectFunc: func(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
			return []evidence.Evidence{NewEvidence().WithModule(id, "0.1.0", "collector").Build()}, nil
		},
	}
}

func (c *StubCollector) ID() string                        { return c.IDValue }
func (c *StubCollector) Name() string                      { return c.NameValue }
func (c *StubCollector) Version() string                   { return c.VersionValue }
func (c *StubCollector) SourceSystem() string              { return c.SourceSystemValue }
func (c *StubCollector) EvidenceTypes() []int              { return c.EvidenceTypeValues }
func (c *StubCollector) CredentialRequirements() []module.CredentialReq { return c.CredReqs }

func (c *StubCollector) Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	if c.CollectFunc != nil {
		return c.CollectFunc(ctx, config)
	}
	return nil, nil
}

// StubTester is a configurable fake that satisfies module.Tester.
type StubTester struct {
	IDValue           string
	NameValue         string
	VersionValue      string
	SourceSystemValue string
	EvidenceTypeValues []int
	CredReqs          []module.CredentialReq
	SafetyValue       module.SafetyClassification
	ScopeValue        module.EnvironmentScope
	PreFlightValues   []string
	CleanupValues     []string
	TestFunc          func(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}

// Compile-time interface check.
var _ module.Tester = (*StubTester)(nil)

// NewStubTester returns a StubTester with sensible defaults.
func NewStubTester(id string) *StubTester {
	return &StubTester{
		IDValue:           id,
		NameValue:         "Stub Tester: " + id,
		VersionValue:      "0.1.0",
		SourceSystemValue: "test",
		EvidenceTypeValues: []int{9999},
		SafetyValue:       module.SafetyClassSafe,
		ScopeValue:        module.ScopeIsolated,
		PreFlightValues:   []string{"check test environment"},
		CleanupValues:     nil,
		TestFunc: func(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
			return []evidence.Evidence{
				NewEvidence().
					WithModule(id, "0.1.0", "tester").
					WithConfidence(evidence.ActiveVerification).
					WithTranscript().
					Build(),
			}, nil
		},
	}
}

func (t *StubTester) ID() string                        { return t.IDValue }
func (t *StubTester) Name() string                      { return t.NameValue }
func (t *StubTester) Version() string                   { return t.VersionValue }
func (t *StubTester) SourceSystem() string              { return t.SourceSystemValue }
func (t *StubTester) EvidenceTypes() []int              { return t.EvidenceTypeValues }
func (t *StubTester) CredentialRequirements() []module.CredentialReq { return t.CredReqs }
func (t *StubTester) SafetyClass() module.SafetyClassification      { return t.SafetyValue }
func (t *StubTester) EnvironmentScope() module.EnvironmentScope      { return t.ScopeValue }
func (t *StubTester) PreFlightChecks() []string                      { return t.PreFlightValues }
func (t *StubTester) CleanupProcedures() []string                    { return t.CleanupValues }

func (t *StubTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	if t.TestFunc != nil {
		return t.TestFunc(ctx, config)
	}
	return nil, nil
}
