package heldledger

import "fmt"

// scopedFirstHeld is a conservative first-input write-ahead fence. It does
// not authorize input, establish witness truth, or implement release.
func scopedFirstHeld(intent State, expected GenesisScope) (State, error) {
 if intent.Version != ScopedVersion || intent.Scope == nil || *intent.Scope != expected ||
  !expected.valid() || intent.Sequence != 2 || !intent.AdmissionIntent || intent.Held ||
  intent.Key != "" || intent.ReleasePhase != "" || intent.KernelWitnessHash != "" ||
  intent.LastReleaseEventSequence != 0 || intent.LastReleaseProofHash != "" ||
  !validGenesisHex(intent.GenesisNonce) || !validGenesisHex(intent.GenesisOperation) ||
  !validGenesisHex(intent.GenesisEvidenceHash) {
  return State{}, ErrInvalid
 }
 next := intent
 scope := expected
 next.Scope = &scope
 next.Sequence = 3
 next.AdmissionIntent = false
 next.Held = true
 next.Key = KeyA
 return next, nil
}

func sameScopedRecord(a, b State) bool {
 if a.Scope == nil || b.Scope == nil || *a.Scope != *b.Scope {
  return false
 }
 a.Scope, b.Scope = nil, nil
 return a == b
}

// SealScopedFirstHeld persists HELD before any prospective physical input.
// Call only under the original live ScopedGenesisOwner, using its exact
// successful in-memory intent (never a record reconstructed on restart).
// It cannot return a lease or grant; even a successfully sealed journal
// remains unavailable to legacy admission/release. The caller must perform
// independently observed fence and input checks before any future activation.
func (s Store) SealScopedFirstHeld(expected GenesisScope, intent State) (State, error) {
 return s.sealScopedFirstHeld(expected, intent, s.writeAtomic)
}

func (s Store) sealScopedFirstHeld(expected GenesisScope, intent State, write func(State) error) (State, error) {
 next, err := scopedFirstHeld(intent, expected)
 if err != nil || write == nil {
  return State{}, ErrInvalid
 }
 current, err := s.ReadScopedAdmissionIntent(expected)
 if err != nil {
  return State{}, err
 }
 if !sameScopedRecord(current, intent) {
  return State{}, ErrConflict
 }
 if err = write(next); err != nil {
  return State{}, fmt.Errorf("scoped first-input seal remains unavailable: %w", err)
 }
 return next, nil
}

// ReadScopedFirstHeld verifies an exact sealed record for observation only.
// This is not a recovery constructor; no API clears or re-admits this phase.
func (s Store) ReadScopedFirstHeld(expected GenesisScope, intent State) (State, error) {
 next, err := scopedFirstHeld(intent, expected)
 if err != nil {
  return State{}, err
 }
 current, err := s.readDecodedState()
 if err != nil {
  return State{}, err
 }
 if !sameScopedRecord(current, next) {
  return State{}, ErrConflict
 }
 return current, nil
}
