package main

import "testing"

// Negative fixture for #14 acceptance: a failing product test must turn
// ci-gate red. Reverted in the next commit.
func TestCIRedFixture(t *testing.T) {
	t.Fatal("deliberate failure: ci-gate must be red")
}
