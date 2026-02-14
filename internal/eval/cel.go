package eval

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/grcengineering/ocean/internal/evidence"
)

// MaxExpressionDepth is the maximum allowed AST depth for a CEL expression.
// Expressions deeper than this are rejected to prevent DoS via overly complex
// evaluation logic. A depth of 12 is generous for typical control evaluation
// expressions while still preventing abuse.
const MaxExpressionDepth = 12

// MaxCELExpressionLength is the maximum number of characters allowed in a CEL
// expression string. Expressions exceeding this length are rejected before
// compilation to prevent resource exhaustion.
const MaxCELExpressionLength = 10000

// MaxCELASTDepth is the maximum allowed nesting depth of parentheses, brackets,
// and braces in a CEL expression. This is a syntactic pre-check before the more
// expensive AST-based depth check.
const MaxCELASTDepth = 50

// ValidateExpressionComplexity checks if a CEL expression is within acceptable
// complexity limits. It verifies that the expression does not exceed the maximum
// character length and that bracket nesting does not exceed the maximum depth.
// Returns an error if the expression is too complex.
func ValidateExpressionComplexity(expr string) error {
	if len(expr) > MaxCELExpressionLength {
		return fmt.Errorf("CEL expression too long: %d characters exceeds maximum of %d", len(expr), MaxCELExpressionLength)
	}

	// Check nesting depth by counting max nesting of parentheses/brackets/braces.
	depth := 0
	maxDepth := 0
	for _, ch := range expr {
		if ch == '(' || ch == '[' || ch == '{' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if ch == ')' || ch == ']' || ch == '}' {
			depth--
		}
	}

	if maxDepth > MaxCELASTDepth {
		return fmt.Errorf("CEL expression too deeply nested: depth %d exceeds maximum of %d", maxDepth, MaxCELASTDepth)
	}

	return nil
}

// CompiledExpression wraps a compiled CEL program ready for evaluation.
// It also retains the original expression text for logging and attestation.
type CompiledExpression struct {
	program    cel.Program
	expression string
}

// Expression returns the original CEL expression text.
func (c *CompiledExpression) Expression() string {
	return c.expression
}

// celEnv is the package-level CEL environment, lazily initialized.
var celEnv *cel.Env

// NewCELEnvironment creates a new CEL environment configured with OCEAN's
// evidence evaluation variables:
//
//   - evidence: list of evidence maps (list(dyn))
//   - status_counts: map of status counts (map(string, dyn))
//   - has_active: bool flag for active verification presence
//   - has_passive: bool flag for passive observation presence
//   - control: map of control fields (map(string, dyn))
func NewCELEnvironment() (*cel.Env, error) {
	env, err := cel.NewEnv(
		cel.Variable("evidence", cel.ListType(cel.DynType)),
		cel.Variable("status_counts", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("has_active", cel.BoolType),
		cel.Variable("has_passive", cel.BoolType),
		cel.Variable("control", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	return env, nil
}

// getEnv returns the package-level CEL environment, creating it if needed.
func getEnv() (*cel.Env, error) {
	if celEnv != nil {
		return celEnv, nil
	}
	env, err := NewCELEnvironment()
	if err != nil {
		return nil, err
	}
	celEnv = env
	return celEnv, nil
}

// CompileExpression parses and type-checks a CEL expression against OCEAN's
// evidence evaluation environment. Returns a CompiledExpression ready for
// evaluation, or an error with position information if compilation fails.
//
// T092: syntax and type checking
// T103: error messages include line/column position
func CompileExpression(expr string) (*CompiledExpression, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("CEL expression is empty")
	}

	// T192: Pre-check expression complexity before expensive compilation.
	if err := ValidateExpressionComplexity(expr); err != nil {
		return nil, err
	}

	env, err := getEnv()
	if err != nil {
		return nil, err
	}

	// Parse and check the expression.
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation error: %w", issues.Err())
	}

	// Verify the output type is bool.
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL expression must return bool, got %v", ast.OutputType())
	}

	// T192: Check AST depth to reject overly complex expressions.
	depth := maxASTDepth(ast)
	if depth > MaxExpressionDepth {
		return nil, fmt.Errorf("CEL expression too complex: depth %d exceeds maximum %d", depth, MaxExpressionDepth)
	}

	// Build the program.
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation error: %w", err)
	}

	return &CompiledExpression{
		program:    prg,
		expression: expr,
	}, nil
}

// CheckExpressionDepth compiles a CEL expression and returns its AST depth.
// This is useful for pre-validating expressions before storing them.
func CheckExpressionDepth(expr string) (int, error) {
	if strings.TrimSpace(expr) == "" {
		return 0, fmt.Errorf("CEL expression is empty")
	}

	env, err := getEnv()
	if err != nil {
		return 0, err
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return 0, fmt.Errorf("CEL compilation error: %w", issues.Err())
	}

	return maxASTDepth(ast), nil
}

// maxASTDepth walks the compiled AST and returns the maximum depth.
// Uses cel-go's NavigableExpr which provides a Depth() method.
func maxASTDepth(ast *cel.Ast) int {
	navRoot := celast.NavigateAST(ast.NativeRep())
	maxDepth := 0
	walkDepth(navRoot, &maxDepth)
	return maxDepth
}

// walkDepth traverses the navigable AST tree, tracking the maximum depth seen.
func walkDepth(expr celast.NavigableExpr, maxDepth *int) {
	d := expr.Depth()
	if d > *maxDepth {
		*maxDepth = d
	}
	for _, child := range expr.Children() {
		walkDepth(child, maxDepth)
	}
}

// Evaluate runs a compiled CEL expression against a set of evidence records.
// It converts the evidence into the activation map expected by the CEL
// environment and evaluates the compiled program.
//
// T093: core evaluation
// T104: missing fields return unknown status, not crash
func Evaluate(compiled *CompiledExpression, evidences []evidence.Evidence) (bool, error) {
	if compiled == nil {
		return false, fmt.Errorf("compiled expression is nil")
	}

	// Build the activation map from evidence.
	activation := EvidencesToActivation(evidences)

	// Add an empty control map (can be populated by caller if needed).
	if _, ok := activation["control"]; !ok {
		activation["control"] = map[string]interface{}{}
	}

	// Evaluate the CEL program.
	out, _, err := compiled.program.Eval(activation)
	if err != nil {
		// T104: gracefully handle missing fields or evaluation errors.
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}

	// Convert the result to a Go bool.
	if out.Type() != types.BoolType {
		return false, fmt.Errorf("CEL expression returned %v, expected bool", out.Type())
	}

	return out.Value().(bool), nil
}
