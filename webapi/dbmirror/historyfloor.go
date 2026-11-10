package dbmirror

import (
	"fmt"
	"math"
	"strings"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/parser"
)

// The history archive prunes on HistoryOrderAttr: it is zone-mapped, and
// the planner turns a top-level "EnteredHistoryTime >= N" conjunct into a
// probe. It cannot do the same for the job's own times. QDate carries no
// zone map at all, so "QDate >= S && QDate < E" -- the calendar's
// drill-down, and the obvious way to ask for "jobs submitted that day" --
// reads every record the archive holds.
//
// But the stamp bounds those times from below. htcondordb sets
// EnteredHistoryTime on every record it archives to the job's terminal
// status transition (EnteredCurrentStatus), falling back to
// CompletionDate and then to the time it read the record; an imported
// record gets the import time. A job is submitted, starts and completes
// before it reaches that transition, so on every archived record
//
//	QDate, CompletionDate, EnteredCurrentStatus <= EnteredHistoryTime
//
// up to clock skew, and a constraint that requires one of them to be at
// least S also requires EnteredHistoryTime to be at least about S.
// HistoryFloor finds that S and WithHistoryFloor adds the conjunct, so
// the archive skips every segment that ended before the window began.
//
// The skew is real: QDate is stamped by the submitting client's clock,
// the transition by the schedd's, and a job removed seconds after a
// submit from a host running ahead enters history "before" it was
// submitted. historyFloorSlack absorbs that, at the cost of reading one
// extra day of segments.
//
// What it cannot absorb is a record whose times were rewritten after the
// fact -- QDate and EnteredCurrentStatus are not immutable job attributes,
// so an owner can condor_qedit QDate to a date after the job left the
// queue. Such a record is dropped from a window it would otherwise match.
// That is the price of the floor; it applies only to reads of a mirror's
// archive, where it is the difference between reading a window and
// reading all of history, and never to a schedd's history scan or the
// live jobs table, which have no EnteredHistoryTime to prune on.
//
// This is only sound where every record carries EnteredHistoryTime. The
// single-AP mirror's archive does; a federation hub's need not, and a
// read there must add the floor only where it already requires the
// attribute to be defined.
const historyFloorSlack = 86400

// historyFloorAttrs are the attributes a lower bound on which implies one
// on HistoryOrderAttr, with the slack each needs. HistoryOrderAttr bounds
// itself exactly; it is listed so a disjunction that mixes it with the
// others ("CompletionDate >= S || EnteredHistoryTime >= S") still yields
// a floor.
var historyFloorAttrs = map[string]int64{
	"qdate":                historyFloorSlack,
	"completiondate":       historyFloorSlack,
	"enteredcurrentstatus": historyFloorSlack,
	"enteredhistorytime":   0,
}

// HistoryFloor returns the lower bound on EnteredHistoryTime implied by
// constraint holding on an archived history record, and whether there is
// a useful one (a positive bound). An unparseable constraint has none.
//
// The bound is derived structurally and errs low: an && takes the larger
// of its operands' floors (either one alone must hold), an || the smaller
// (only one of them need hold, and both must have a floor), and anything
// else -- a negation, a conditional, a function call, a comparison with
// a non-literal side or with CurrentTime -- contributes nothing.
func HistoryFloor(constraint string) (int64, bool) {
	e, err := parser.ParseExpr(constraint)
	if err != nil {
		return 0, false
	}
	f, ok := exprFloor(classad.FoldConstants(e))
	if !ok || f <= 0 {
		return 0, false
	}
	return f, true
}

// WithHistoryFloor ANDs the implied "EnteredHistoryTime >= floor" onto
// constraint, as a top-level conjunct the archive planner can probe. It
// returns constraint unchanged when there is no floor, or when a
// top-level conjunct already bounds EnteredHistoryTime at least as
// tightly.
//
// Only for a read of a single-AP mirror's history archive; see
// historyFloorSlack.
func WithHistoryFloor(constraint string) string {
	floor, ok := HistoryFloor(constraint)
	if !ok {
		return constraint
	}
	if e, err := parser.ParseExpr(constraint); err == nil {
		for _, c := range topConjuncts(classad.FoldConstants(e), nil) {
			if attr, n, ok := lowerBound(c); ok && attr == "enteredhistorytime" && n >= floor {
				return constraint
			}
		}
	}
	return fmt.Sprintf("(%s) && %s >= %d", constraint, HistoryOrderAttr, floor)
}

// exprFloor is HistoryFloor on a parsed expression.
func exprFloor(e ast.Expr) (int64, bool) {
	e = unparen(e)
	if b, ok := e.(*ast.BinaryOp); ok {
		switch b.Op {
		case "&&":
			// The constraint is true only if both operands are true, so
			// either one's floor holds.
			l, lok := exprFloor(b.Left)
			r, rok := exprFloor(b.Right)
			switch {
			case lok && rok:
				return max(l, r), true
			case lok:
				return l, true
			case rok:
				return r, true
			}
			return 0, false
		case "||":
			// True when either is: a floor only when both have one.
			l, lok := exprFloor(b.Left)
			r, rok := exprFloor(b.Right)
			if lok && rok {
				return min(l, r), true
			}
			return 0, false
		}
	}
	attr, n, ok := lowerBound(e)
	if !ok {
		return 0, false
	}
	slack, known := historyFloorAttrs[attr]
	if !known {
		return 0, false
	}
	if n < math.MinInt64+slack {
		return 0, false
	}
	return n - slack, true
}

// lowerBound recognizes a comparison that, when true, puts a self-scoped
// attribute at or above an integer: "A >= n", "A > n", "A == n",
// "A is n" and their mirror images. It returns the lower-cased attribute
// name and the bound. A real literal is rounded down, which keeps the
// bound a bound; a non-finite one is not recognized.
func lowerBound(e ast.Expr) (string, int64, bool) {
	b, ok := unparen(e).(*ast.BinaryOp)
	if !ok {
		return "", 0, false
	}
	op := b.Op
	left, right := unparen(b.Left), unparen(b.Right)
	if _, isRef := left.(*ast.AttributeReference); !isRef {
		// "n <= A" is "A >= n".
		left, right = right, left
		switch op {
		case "<=":
			op = ">="
		case "<":
			op = ">"
		case "==", "is":
		default:
			return "", 0, false
		}
	}
	switch op {
	case ">=", ">", "==", "is":
	default:
		return "", 0, false
	}
	ref, ok := left.(*ast.AttributeReference)
	if !ok || (ref.Scope != ast.NoScope && ref.Scope != ast.MyScope) {
		return "", 0, false
	}
	var n int64
	switch lit := right.(type) {
	case *ast.IntegerLiteral:
		n = lit.Value
	case *ast.RealLiteral:
		if math.IsNaN(lit.Value) || math.IsInf(lit.Value, 0) ||
			lit.Value >= math.MaxInt64 || lit.Value < math.MinInt64 {
			return "", 0, false
		}
		n = int64(math.Floor(lit.Value))
	default:
		return "", 0, false
	}
	return strings.ToLower(ref.Name), n, true
}

// topConjuncts flattens the top-level && spine of e.
func topConjuncts(e ast.Expr, acc []ast.Expr) []ast.Expr {
	e = unparen(e)
	if b, ok := e.(*ast.BinaryOp); ok && b.Op == "&&" {
		return topConjuncts(b.Right, topConjuncts(b.Left, acc))
	}
	return append(acc, e)
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok || p.Inner == nil {
			return e
		}
		e = p.Inner
	}
}
