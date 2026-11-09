package b

import (
	"example.invalid/suitebudget/budget"
	"testing"
)

// This isolated binary performs bounded work and owns a descendant.
func TestBudgetFixture(t *testing.T) { budget.Fixture(t, "b") }
