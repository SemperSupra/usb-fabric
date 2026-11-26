package runtimeproof

// Recovery observations are a distinct evidence type, NOT normal DOWN/UP
// lease receipts, an attestation provider, a journal write, or a grant.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"sync"

	releasegate "example.org/usb-fabric-r26-releasegate"
)

const recoveryDomain = "USB-Fabric-native-recovery-neutral-Ed25519-v1"
const RecoveryNeutralSource = "guest.evdev.neutral-state"

// RecoveryBinding must come from trusted, durably recorded host launch/lease
// identity and the exact current HELD journal bytes, NOT guest/client input.
// LaunchDigest commits to the enrolled VM launch identity, including the
// independently pinned process incarnation and guest public key. HeldDigest
// commits to the current durable record; Scope.ReleaseSequence must match it.
// The caller, not this cryptographic primitive, validates these observations.
type RecoveryBinding struct {
	Scope        releasegate.Scope `json:"scope"`
	LaunchDigest [32]byte          `json:"launch_digest"`
	HeldDigest   [32]byte          `json:"held_digest"`
}

type RecoveryChallenge struct {
	Binding RecoveryBinding `json:"binding"`
	Nonce   [32]byte        `json:"nonce"`
}

type RecoveryObservation struct {
	Challenge RecoveryChallenge `json:"challenge"`
	Source    string            `json:"source"`
	KeyCode   string            `json:"key_code"`
	Neutral   bool              `json:"neutral"`
	Signature []byte            `json:"signature"`
}

func validRecoveryBinding(pin ed25519.PublicKey, b RecoveryBinding) bool {
	if len(pin) != ed25519.PublicKeySize || bytes.Equal(pin, make([]byte, ed25519.PublicKeySize)) ||
		b.LaunchDigest == ([32]byte{}) || b.HeldDigest == ([32]byte{}) ||
		b.Scope.Generation == 0 || b.Scope.ReleaseSequence == 0 || b.Scope.GuestEpoch != InstanceEpoch(pin) {
		return false
	}
	for _, v := range []string{b.Scope.GuestID, b.Scope.DeviceID, b.Scope.HostEpoch, b.Scope.GuestEpoch, b.Scope.LeaseEpoch} {
		if len(v) == 0 || len(v) > 256 {
			return false
		}
	}
	return true
}

func recoveryMessage(o RecoveryObservation) []byte {
	var b bytes.Buffer
	b.WriteString(recoveryDomain)
	b.WriteByte(0)
	b.Write(o.Challenge.Nonce[:])
	b.Write(o.Challenge.Binding.LaunchDigest[:])
	b.Write(o.Challenge.Binding.HeldDigest[:])
	str := func(v string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		b.Write(n[:])
		b.WriteString(v)
	}
	u64 := func(v uint64) { var n [8]byte; binary.BigEndian.PutUint64(n[:], v); b.Write(n[:]) }
	s := o.Challenge.Binding.Scope
	str(s.GuestID)
	str(s.DeviceID)
	str(s.HostEpoch)
	str(s.GuestEpoch)
	str(s.LeaseEpoch)
	u64(s.Generation)
	u64(s.ReleaseSequence)
	str(o.Source)
	str(o.KeyCode)
	if o.Neutral {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func validNeutral(o RecoveryObservation) bool {
	return o.Source == RecoveryNeutralSource && o.KeyCode == "key-a" && o.Neutral && o.Challenge.Nonce != ([32]byte{})
}

// SignRecoveryNeutral is usable only by an independently authenticated guest
// sensor AFTER reading actual neutral input state. It does not observe evdev
// or prove that a guest-controlled sensor is truthful. Test keys remain test-only.
func SignRecoveryNeutral(priv ed25519.PrivateKey, o RecoveryObservation) (RecoveryObservation, error) {
	if len(priv) != ed25519.PrivateKeySize || !validNeutral(o) || !validRecoveryBinding(priv.Public().(ed25519.PublicKey), o.Challenge.Binding) {
		return RecoveryObservation{}, ErrUntrusted
	}
	o.Signature = ed25519.Sign(priv, recoveryMessage(o))
	return o, nil
}

// Copies share one consumption state; no copying of mutex or independent
// replay window. A new attempt always creates a fresh challenge.
type RecoveryAttempt struct{ state *recoveryAttemptState }
type recoveryAttemptState struct {
	mu        sync.Mutex
	pin       ed25519.PublicKey
	challenge RecoveryChallenge
	consumed  bool
}

func NewRecoveryAttempt(pinned ed25519.PublicKey, binding RecoveryBinding) (*RecoveryAttempt, error) {
	if !validRecoveryBinding(pinned, binding) {
		return nil, ErrUntrusted
	}
	nonce, err := NewHostChallenge()
	if err != nil {
		return nil, err
	}
	return &RecoveryAttempt{state: &recoveryAttemptState{pin: append(ed25519.PublicKey(nil), pinned...), challenge: RecoveryChallenge{Binding: binding, Nonce: nonce}}}, nil
}

func (a *RecoveryAttempt) Challenge() (RecoveryChallenge, error) {
	if a == nil || a.state == nil {
		return RecoveryChallenge{}, ErrUntrusted
	}
	return a.state.challenge, nil
}

// ConfirmNeutral consumes exactly one valid observation for this attempt.
// Success is evidence authentication ONLY. The original retained host owner
// must independently recheck launch identity, journal sequence/digest, QMP
// release ACK, effective isolation and guest sensor truth before any separate
// durable release transaction. There is deliberately no Reclaimable or grant API.
func (a *RecoveryAttempt) ConfirmNeutral(o RecoveryObservation) error {
	if a == nil || a.state == nil {
		return ErrUntrusted
	}
	s := a.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || o.Challenge != s.challenge || !validNeutral(o) || len(o.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(s.pin, recoveryMessage(o), o.Signature) {
		return ErrUntrusted
	}
	s.consumed = true
	return nil
}
