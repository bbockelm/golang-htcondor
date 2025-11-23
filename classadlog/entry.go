package classadlog

// OpType represents the type of log operation in the job queue log
type OpType int

const (
	// OpUnknown represents an unknown or unrecognized operation
	OpUnknown OpType = iota

	// OpNewClassAd creates a new ClassAd with key, MyType, and TargetType
	OpNewClassAd

	// OpDestroyClassAd deletes a ClassAd by key
	OpDestroyClassAd

	// OpSetAttribute sets an attribute value on a ClassAd
	OpSetAttribute

	// OpDeleteAttribute removes an attribute from a ClassAd
	OpDeleteAttribute

	// OpBeginTransaction marks the beginning of a transaction
	// Transactions can typically be ignored for read-only access
	OpBeginTransaction

	// OpEndTransaction marks the end of a transaction
	OpEndTransaction

	// OpLogHistoricalSequenceNumber logs metadata about sequence numbers
	// Can typically be ignored for read-only access
	OpLogHistoricalSequenceNumber
)

// String returns the string representation of an OpType
func (op OpType) String() string {
	switch op {
	case OpNewClassAd:
		return "NewClassAd"
	case OpDestroyClassAd:
		return "DestroyClassAd"
	case OpSetAttribute:
		return "SetAttribute"
	case OpDeleteAttribute:
		return "DeleteAttribute"
	case OpBeginTransaction:
		return "BeginTransaction"
	case OpEndTransaction:
		return "EndTransaction"
	case OpLogHistoricalSequenceNumber:
		return "LogHistoricalSequenceNumber"
	default:
		return "Unknown"
	}
}

// LogEntry represents a single operation in the job queue log
//
// Keys follow the pattern ClusterId.ProcId:
//   - Cluster ads: Keys like "01.-1" (ClusterId starts with 0, ProcId is -1)
//     Example: "01.-1" is the cluster ad for cluster 1
//   - Job ads: Keys like "1.0", "1.1" (regular ClusterId.ProcId)
//     Example: "1.0" is proc 0 of cluster 1
type LogEntry struct {
	// OpType is the operation type
	OpType OpType

	// Key is the ClassAd identifier (ClusterId.ProcId)
	Key string

	// MyType is the ClassAd type (for OpNewClassAd)
	MyType string

	// TargetType is the ClassAd target type (for OpNewClassAd)
	TargetType string

	// Name is the attribute name (for OpSetAttribute and OpDeleteAttribute)
	Name string

	// Value is the attribute value as a string (for OpSetAttribute)
	// This is the unparsed ClassAd expression that needs to be parsed
	Value string
}
