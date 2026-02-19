// Package testutil provides shared test helpers for OCEAN's test suite.
// It is an internal package and should only be imported by _test.go files.
//
// Key helpers:
//   - EvidenceBuilder: fluent builder for evidence.Evidence test data
//   - MockAPIServer: httptest wrapper for mocking external APIs
//   - StubCollector/StubTester: configurable fakes for module interfaces
//   - MemoryStore: thread-safe in-memory storage.Store implementation
//   - AssertValidEvidence: common assertion helpers
//   - LoadFixture: read canned API responses from tests/fixtures/
package testutil
