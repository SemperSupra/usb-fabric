//go:build linux

package heldledger

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/runtimeproof"
)

func nativeBoundFixture(t *testing.T)(Store,ed25519.PublicKey,ed25519.PrivateKey,NativeHeldIdentity,NativeLaunchPin){
 t.Helper()
 d:=t.TempDir()
 if e:=os.Chmod(d,0700);e!=nil{t.Fatal(e)}
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 digest:=sha256.Sum256([]byte("protected-launch-fixture"))
 id:=NativeHeldIdentity{Scope:releasegate.Scope{GuestID:"guest",DeviceID:"kbd",HostEpoch:"host",GuestEpoch:runtimeproof.InstanceEpoch(pub),LeaseEpoch:"old-lease",Generation:7,ReleaseSequence:1},LaunchDigest:hex.EncodeToString(digest[:])}
 pin:=NativeLaunchPin{GuestID:id.Scope.GuestID,DeviceID:id.Scope.DeviceID,LaunchDigest:id.LaunchDigest}
 return Store{Path:filepath.Join(d,"held.json")},pub,priv,id,pin
}

func TestNativeBoundHeldExactBytesAndLegacyDenial(t *testing.T){
 s,pub,priv,id,pin:=nativeBoundFixture(t)
 if _,_,e:=s.ReadNativeBoundHeld(pin,pub);e==nil{t.Fatal("missing record admitted")}
 got,e:=s.PersistNativeBoundHeld(0,id,pub)
 if e!=nil||!got.Held||got.Version!=NativeBoundVersion||got.Sequence!=1||got.Identity!=id{t.Fatal("bound write failed",got,e)}
 raw,e:=os.ReadFile(s.Path);if e!=nil{t.Fatal(e)}
 r,b,e:=s.ReadNativeBoundHeld(pin,pub)
 if e!=nil||r!=got||b.Scope!=id.Scope||b.HeldDigest!=sha256.Sum256(raw){t.Fatal("bad exact record binding",e)}
 a,e:=runtimeproof.NewRecoveryAttempt(pub,b);if e!=nil{t.Fatal(e)}
 c,e:=a.Challenge();if e!=nil{t.Fatal(e)}
 obs,e:=runtimeproof.SignRecoveryNeutral(priv,runtimeproof.RecoveryObservation{Challenge:c,Source:runtimeproof.RecoveryNeutralSource,KeyCode:KeyA,Neutral:true});if e!=nil{t.Fatal(e)}
 if e=a.ConfirmNeutral(obs);e!=nil{t.Fatal(e)}
 if _,e=s.Read();e==nil{t.Fatal("legacy read admitted v3")}
 if _,e=s.Transition(1,false);e==nil{t.Fatal("legacy clear admitted")}
 if _,e=s.RequestRelease(1);e==nil{t.Fatal("legacy release admitted")}
 if _,e=s.PersistNativeBoundHeld(0,id,pub);e==nil{t.Fatal("replayed write")}
 after,e:=os.ReadFile(s.Path);if e!=nil||!bytes.Equal(raw,after){t.Fatal("denial changed journal",e)}
 // Equivalent JSON with changed exact bytes must have a different binding.
 changed:=append(append([]byte(nil),raw...),' ')
 if e=os.WriteFile(s.Path,changed,0600);e!=nil{t.Fatal(e)}
 _,next,e:=s.ReadNativeBoundHeld(pin,pub)
 if e!=nil||next.HeldDigest!=sha256.Sum256(changed)||next.HeldDigest==b.HeldDigest{t.Fatal("digest normalized or changed bytes rejected",e)}
 // Even a validly signed old challenge cannot satisfy the newly bound record.
 nextAttempt,e:=runtimeproof.NewRecoveryAttempt(pub,next);if e!=nil{t.Fatal(e)}
 if e=nextAttempt.ConfirmNeutral(obs);e==nil{t.Fatal("old record observation accepted")}
 t.Log("NATIVE_BOUND_HELD_EXACT_BYTES_OLD_SCOPE_LEGACY_DENIAL=PASS")
}

func TestNativeBoundHeldRejectsForeignAndMalformed(t *testing.T){
 s,pub,_,id,pin:=nativeBoundFixture(t)
 for _,change:=range []func(*NativeHeldIdentity){
  func(x *NativeHeldIdentity){x.Scope.Generation=0},
  func(x *NativeHeldIdentity){x.Scope.ReleaseSequence++},
  func(x *NativeHeldIdentity){x.Scope.GuestEpoch="foreign"},
  func(x *NativeHeldIdentity){x.Scope.LeaseEpoch=strings.Repeat("x",257)},
  func(x *NativeHeldIdentity){x.LaunchDigest=strings.Repeat("0",64)},
  func(x *NativeHeldIdentity){x.LaunchDigest="bad"},
 }{
  bad:=id;change(&bad)
  if _,e:=s.PersistNativeBoundHeld(0,bad,pub);e==nil{t.Fatal("bad binding written")}
  if _,e:=os.Lstat(s.Path);!os.IsNotExist(e){t.Fatal("denied binding created journal",e)}
 }
 if _,e:=s.PersistNativeBoundHeld(1,id,pub);e==nil{t.Fatal("stale sequence accepted")}
 if _,e:=s.PersistNativeBoundHeld(0,id,pub);e!=nil{t.Fatal(e)}
 raw,e:=os.ReadFile(s.Path);if e!=nil{t.Fatal(e)}
 foreign,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 if _,_,e=s.ReadNativeBoundHeld(pin,foreign);e==nil{t.Fatal("foreign public key accepted")}
 for _,change:=range []func(*NativeLaunchPin){
  func(x *NativeLaunchPin){x.GuestID="other"},
  func(x *NativeLaunchPin){x.DeviceID="other"},
  func(x *NativeLaunchPin){x.LaunchDigest=strings.Repeat("aa",32)},
 }{
  bad:=pin;change(&bad)
  if _,_,e=s.ReadNativeBoundHeld(bad,pub);e==nil{t.Fatal("foreign trusted launch accepted")}
 }
 for _,bad:=range []string{
  strings.Replace(string(raw),"\"held\":true","\"held\":true,\"HELD\":false",1),
  strings.Replace(string(raw),"\"scope\":{","\"scope\":{\"guest_id\":\"bad\",",1),
  strings.Replace(string(raw),"\"native_identity\":{","\"native_identity\":{\"launch_digest\":\"bad\",",1),
  strings.Replace(string(raw),"\"scope\":{","\"scope\":{\"unexpected\":1,",1),
  strings.Replace(string(raw),"\"version\":3","\"version\":2",1),
 }{
  if bad==string(raw){t.Fatal("mutation did not change fixture")}
  if e=os.WriteFile(s.Path,[]byte(bad),0600);e!=nil{t.Fatal(e)}
  if _,_,e=s.ReadNativeBoundHeld(pin,pub);e==nil{t.Fatal("malformed journal accepted",bad)}
 }
 if e=os.WriteFile(s.Path,raw,0600);e!=nil{t.Fatal(e)}
 if e=os.Chmod(filepath.Dir(s.Path),0755);e!=nil{t.Fatal(e)}
 if _,_,e=s.ReadNativeBoundHeld(pin,pub);e==nil{t.Fatal("unprotected parent accepted")}
 t.Log("NATIVE_BOUND_HELD_FOREIGN_MALFORMED_AND_PARENT_DENIED=PASS")
}

func TestNativeBoundHeldAmbiguousWriteAndOtherFormats(t *testing.T){
 s,pub,_,id,pin:=nativeBoundFixture(t)
 fault:=errors.New("injected error after durable visibility")
 _,e:=s.persistNativeBoundHeld(0,id,pub,func(r NativeHeldRecord)error{if e:=s.writeAtomicRecord(r);e!=nil{return e};return fault})
 if !errors.Is(e,fault){t.Fatal("write failure lost",e)}
 if r,_,e:=s.ReadNativeBoundHeld(pin,pub);e!=nil||!r.Held{t.Fatal("visible HELD lost",e)}
 if _,e=s.PersistNativeBoundHeld(0,id,pub);e==nil{t.Fatal("ambiguous write retried")}
 legacy,_,_,legacyID,_:=nativeBoundFixture(t)
 if _,e=legacy.Transition(0,true);e!=nil{t.Fatal(e)}
 legacyID.Scope.ReleaseSequence=2
 if _,e=legacy.PersistNativeBoundHeld(1,legacyID,pub);e==nil{t.Fatal("legacy HELD converted")}
 scoped,scope:=scopedFixture(t)
 if _,e=scoped.CreateScopedHeldGenesis(scope);e!=nil{t.Fatal(e)}
 id.Scope.ReleaseSequence=2
 if _,e=scoped.PersistNativeBoundHeld(1,id,pub);e==nil{t.Fatal("scoped HELD converted")}
 t.Log("NATIVE_BOUND_HELD_AMBIGUOUS_WRITE_NO_FORMAT_DOWNGRADE=PASS")
}
