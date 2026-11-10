package config

// Converting a real to an integer when the real does not fit is UNDEFINED in
// C++, and HTCondor's ClassAd evaluator does it with a bare cast -- so what
// comes out is whatever the host's instruction produces, and the two common
// instructions produce different answers:
//
//	                       1e20            -1e20           NaN
//	x86-64 cvttsd2si       INT64_MIN       INT64_MIN       INT64_MIN
//	arm64  fcvtzs          INT64_MAX       INT64_MIN       0
//
// x86-64 has one "integer indefinite" value for every case it cannot
// represent; arm64 saturates towards the value it was given and sends NaN to
// zero.
//
// This library's job is to produce the ad that the condor_submit NEXT TO IT
// would, so it follows the host rather than picking one. The differential
// fuzzer is what noticed: $INT(1E20) is INT64_MIN here and INT64_MAX in the
// oracle, but only on Apple Silicon -- CI runs x86-64, where the two agreed
// and nothing was wrong.
//
// Each architecture here has been MEASURED against the oracle, not inferred.
// An architecture that is not listed gets the x86-64 answer, which is a
// guess; measure it before adding it, because the instruction's behaviour on
// NaN in particular is not something to reason out from the manual.

// truncToInt64 converts a real to an integer the way a C++ cast does on this
// architecture. In-range values truncate towards zero on every architecture,
// which is the only part of this the C++ standard defines.
func truncToInt64(f float64) int64 { return truncOutOfRange(f) }
