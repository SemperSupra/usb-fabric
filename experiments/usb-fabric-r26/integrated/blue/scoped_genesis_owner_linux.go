//go:build linux

package blue

import (
 "crypto/ed25519"
 "errors"
 "path/filepath"
 "sort"
 "sync"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

// ScopedGenesisOwner retains the original OS owner primitives. Copies share
// the same session, mutex, closure and one-shot preparation state. It is not
// another Manager, grant authority or a distributed lock.
type ScopedGenesisOwner struct { session *scopedGenesisSession }
type scopedGenesisSession struct {
 mu sync.Mutex
 scope heldledger.GenesisScope
 store heldledger.Store
 locks []*USBIPRecoveredOwner
 closed bool
 intent *heldledger.State
}

func OpenScopedGenesisOwner(scope heldledger.GenesisScope, store heldledger.Store) (*ScopedGenesisOwner, error) {
 if !filepath.IsAbs(store.Path) || filepath.Clean(store.Path) != store.Path {
  return nil, ErrQuarantined
 }
 parent, e := filepath.EvalSymlinks(filepath.Dir(store.Path))
 if e != nil || parent != filepath.Dir(store.Path) {
  return nil, ErrQuarantined
 }
 keys, e := scope.StableConflictKeys()
 if e != nil {
  return nil, ErrQuarantined
 }
 keys = append(keys, "journal:"+store.Path)
 sort.Strings(keys)
 s := &scopedGenesisSession{scope: scope, store: store}
 o := &ScopedGenesisOwner{session: s}
 for _, key := range keys {
  lock, e := acquireUSBIPRecoveredOwner("scoped-v2:"+key, "resource-conflict", store.Path)
  if e != nil {
   _ = o.Close()
   return nil, e
  }
  s.locks = append(s.locks, lock)
 }
 return o, nil
}

func (o *ScopedGenesisOwner) CreateHeldGenesis() (heldledger.State, error) {
 if o == nil || o.session == nil {
  return heldledger.State{}, ErrQuarantined
 }
 s := o.session
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.closed {
  return heldledger.State{}, ErrQuarantined
 }
 return s.store.CreateScopedHeldGenesis(s.scope)
}

func (o *ScopedGenesisOwner) PrepareAdmission(operation string, witnesses []heldledger.GenesisWitness, pins map[string]ed25519.PublicKey) (heldledger.State, error) {
 if o == nil || o.session == nil {
  return heldledger.State{}, ErrQuarantined
 }
 s := o.session
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.closed {
  return heldledger.State{}, ErrQuarantined
 }
 if s.intent != nil {
  return heldledger.State{}, heldledger.ErrConflict
 }
 st, e := s.store.PrepareScopedAdmission(s.scope, operation, witnesses, pins)
 if e != nil {
  return heldledger.State{}, e
 }
 // Own an independent copy; do not let callers mutate the retained scope
 // through the State returned by PrepareAdmission.
 copyState := st
 scope := s.scope
 copyState.Scope = &scope
 s.intent = &copyState
 return st, nil
}

// SealFirstHeld consumes the exact same live owner's successful preparation.
// No recovered owner can reconstruct it from disk; no error permits retry.
// This is a conservative journal seal only, never permission to emit input.
func (o *ScopedGenesisOwner) SealFirstHeld() (heldledger.State, error) {
 if o == nil || o.session == nil {
  return heldledger.State{}, ErrQuarantined
 }
 s := o.session
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.closed || s.intent == nil {
  return heldledger.State{}, ErrQuarantined
 }
 intent := *s.intent
 s.intent = nil
 return s.store.SealScopedFirstHeld(s.scope, intent)
}

func (o *ScopedGenesisOwner) Close() error {
 if o == nil || o.session == nil {
  return nil
 }
 s := o.session
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.closed {
  return nil
 }
 s.closed = true
 s.intent = nil
 var err error
 for i := len(s.locks)-1; i >= 0; i-- {
  err = errors.Join(err, s.locks[i].Close())
 }
 s.locks = nil
 return err
}
