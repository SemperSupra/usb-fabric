package runtimeproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	releasegate "example.org/usb-fabric-r26-releasegate"
)

func recoveryFixture(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, RecoveryBinding) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return pub, priv, RecoveryBinding{Scope: releasegate.Scope{GuestID: "guest", DeviceID: "kbd", HostEpoch: "host", GuestEpoch: InstanceEpoch(pub), LeaseEpoch: "lease", Generation: 7, ReleaseSequence: 9}, LaunchDigest: sha256.Sum256([]byte("pinned launch")), HeldDigest: sha256.Sum256([]byte("exact held record"))}
}

func recoverySigned(t *testing.T, a *RecoveryAttempt, priv ed25519.PrivateKey) RecoveryObservation {
	t.Helper()
	c, e := a.Challenge()
	if e != nil {
		t.Fatal(e)
	}
	o, e := SignRecoveryNeutral(priv, RecoveryObservation{Challenge: c, Source: RecoveryNeutralSource, KeyCode: "key-a", Neutral: true})
	if e != nil {
		t.Fatal(e)
	}
	return o
}

func TestRecoveryBindingAndFreshNeutral(t *testing.T) {
	pub, priv, b := recoveryFixture(t)
	a, e := NewRecoveryAttempt(pub, b)
	if e != nil {
		t.Fatal(e)
	}
	good := recoverySigned(t, a, priv)
	_, foreign, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	mutations := map[string]func(*RecoveryObservation){
		"wrong-nonce":            func(o *RecoveryObservation) { o.Challenge.Nonce[0] ^= 1 },
		"wrong-launch":           func(o *RecoveryObservation) { o.Challenge.Binding.LaunchDigest[0] ^= 1 },
		"wrong-held-bytes":       func(o *RecoveryObservation) { o.Challenge.Binding.HeldDigest[0] ^= 1 },
		"wrong-old-generation":   func(o *RecoveryObservation) { o.Challenge.Binding.Scope.Generation++ },
		"wrong-release-sequence": func(o *RecoveryObservation) { o.Challenge.Binding.Scope.ReleaseSequence++ },
		"wrong-guest-epoch":      func(o *RecoveryObservation) { o.Challenge.Binding.Scope.GuestEpoch = "other" },
		"wrong-source":           func(o *RecoveryObservation) { o.Source = "guest.enrollment" },
		"wrong-key":              func(o *RecoveryObservation) { o.KeyCode = "mouse-left" },
		"not-neutral":            func(o *RecoveryObservation) { o.Neutral = false },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := good
			change(&bad)
			bad.Signature = ed25519.Sign(priv, recoveryMessage(bad))
			if a.ConfirmNeutral(bad) == nil {
				t.Fatal("modified but correctly signed claim accepted")
			}
		})
	}
	bad := good
	bad.Signature = ed25519.Sign(foreign, recoveryMessage(bad))
	if a.ConfirmNeutral(bad) == nil {
		t.Fatal("foreign key accepted")
	}
	bad = good
	bad.Signature = append([]byte(nil), good.Signature...)
	bad.Signature[0] ^= 1
	if a.ConfirmNeutral(bad) == nil {
		t.Fatal("bad signature accepted")
	}
	bad = good
	bad.Signature = good.Signature[:1]
	if a.ConfirmNeutral(bad) == nil {
		t.Fatal("short signature accepted")
	}
	legacy, e := Sign(priv, Event{Scope: b.Scope, Challenge: good.Challenge.Nonce, Source: "guest.evdev", KeyCode: "key-a", EventSequence: 1})
	if e != nil {
		t.Fatal(e)
	}
	bad = good
	bad.Signature = legacy.Signature
	if a.ConfirmNeutral(bad) == nil {
		t.Fatal("legacy signature accepted")
	}
	old, e := NewAuthority(pub, b.Scope, good.Challenge.Nonce)
	if e != nil {
		t.Fatal(e)
	}
	legacy.Signature = good.Signature
	if old.ConfirmUp(legacy) == nil || old.Reclaimable() {
		t.Fatal("recovery evidence became legacy release")
	}
	pub[0] ^= 1 // The attempt owns a copy of its independently enrolled pin.
	copyAttempt := *a
	if e = a.ConfirmNeutral(good); e != nil {
		t.Fatal(e)
	}
	if a.ConfirmNeutral(good) == nil || copyAttempt.ConfirmNeutral(good) == nil {
		t.Fatal("same-attempt replay or copy replay")
	}
	next, e := NewRecoveryAttempt(priv.Public().(ed25519.PublicKey), b)
	if e != nil {
		t.Fatal(e)
	}
	c, e := next.Challenge()
	if e != nil || c.Nonce == good.Challenge.Nonce {
		t.Fatal("challenge not fresh")
	}
	if next.ConfirmNeutral(good) == nil {
		t.Fatal("restart replay")
	}
	if e = next.ConfirmNeutral(recoverySigned(t, next, priv)); e != nil {
		t.Fatal(e)
	}
}

func TestRecoveryInvalidBinding(t *testing.T) {
	pub, priv, b := recoveryFixture(t)
	cases := []RecoveryBinding{b, b, b, b, b, b, b}
	cases[0].LaunchDigest = [32]byte{}
	cases[1].HeldDigest = [32]byte{}
	cases[2].Scope.Generation = 0
	cases[3].Scope.ReleaseSequence = 0
	cases[4].Scope.GuestEpoch = "foreign"
	cases[5].Scope.HostEpoch = ""
	cases[6].Scope.LeaseEpoch = strings.Repeat("x", 257)
	for i, v := range cases {
		if _, e := NewRecoveryAttempt(pub, v); e == nil {
			t.Fatalf("invalid binding %d accepted", i)
		}
	}
	if _, e := NewRecoveryAttempt(nil, b); e == nil {
		t.Fatal("nil pin accepted")
	}
	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)
	b.Scope.GuestEpoch = InstanceEpoch(zero)
	if _, e := NewRecoveryAttempt(zero, b); e == nil {
		t.Fatal("zero pin accepted")
	}
	var a RecoveryAttempt
	if _, e := a.Challenge(); e == nil || a.ConfirmNeutral(RecoveryObservation{}) == nil {
		t.Fatal("zero attempt accepted")
	}
	if _, e := SignRecoveryNeutral(priv, RecoveryObservation{}); e == nil {
		t.Fatal("invalid observation signed")
	}
}

func TestRecoveryConcurrentConsumption(t *testing.T) {
	pub, priv, b := recoveryFixture(t)
	a, e := NewRecoveryAttempt(pub, b)
	if e != nil {
		t.Fatal(e)
	}
	o := recoverySigned(t, a, priv)
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copyAttempt := *a
			if copyAttempt.ConfirmNeutral(o) == nil {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("accepted %d concurrent copies", success.Load())
	}
}
