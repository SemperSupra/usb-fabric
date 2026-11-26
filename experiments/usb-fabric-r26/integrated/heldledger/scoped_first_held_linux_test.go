//go:build linux

package heldledger

import (
 "bytes"
 "errors"
 "os"
 "strings"
 "testing"
)

func TestScopedFirstHeldExactIntent(t *testing.T) {
 s,scope,_,op,ws,pins := signedGenesis(t)
 intent,e := s.PrepareScopedAdmission(scope,op,ws,pins)
 if e != nil { t.Fatal(e) }
 before,e := os.ReadFile(s.Path)
 if e != nil { t.Fatal(e) }
 for _,change := range []func(*State){
  func(x *State){x.GenesisOperation = strings.Repeat("cd",32)},
  func(x *State){x.GenesisNonce = strings.Repeat("ef",32)},
  func(x *State){x.GenesisEvidenceHash = strings.Repeat("ff",32)},
  func(x *State){x.Sequence++},
  func(x *State){x.Version = Version},
  func(x *State){x.AdmissionIntent = false},
  func(x *State){x.Held = true},
  func(x *State){foreign:=scope;foreign.DeviceResource="foreign";x.Scope=&foreign},
 } {
  bad:=intent;change(&bad)
  if _,e=s.SealScopedFirstHeld(scope,bad);e==nil {t.Fatal("altered intent accepted")}
  after,e:=os.ReadFile(s.Path);if e!=nil||!bytes.Equal(before,after){t.Fatal("denial mutated journal",e)}
 }
 next,e:=s.SealScopedFirstHeld(scope,intent)
 if e!=nil||next.Sequence!=3||!next.Held||next.AdmissionIntent||next.Key!=KeyA||next.GenesisEvidenceHash!=intent.GenesisEvidenceHash{t.Fatal("seal failed",next,e)}
 if _,e=s.ReadScopedFirstHeld(scope,intent);e!=nil{t.Fatal(e)}
 after,e:=os.ReadFile(s.Path);if e!=nil{t.Fatal(e)}
 if _,e=s.SealScopedFirstHeld(scope,intent);e==nil{t.Fatal("replayed seal")}
 if _,e=s.Read();e==nil{t.Fatal("legacy read admitted")}
 if _,e=s.Transition(3,false);e==nil{t.Fatal("legacy clear admitted")}
 if _,e=s.BeginAdmission(3);e==nil{t.Fatal("legacy grant admitted")}
 final,e:=os.ReadFile(s.Path);if e!=nil||!bytes.Equal(after,final){t.Fatal("replay/legacy changed record",e)}
 t.Log("V2_FIRST_HELD_EXACT_INTENT_AND_LEGACY_DENIAL=PASS")
}

func TestScopedFirstHeldAmbiguousWrite(t *testing.T){
 s,scope,_,op,ws,pins:=signedGenesis(t)
 intent,e:=s.PrepareScopedAdmission(scope,op,ws,pins);if e!=nil{t.Fatal(e)}
 fault:=errors.New("injected error after durable visibility")
 _,e=s.sealScopedFirstHeld(scope,intent,func(st State)error{if e:=s.writeAtomic(st);e!=nil{return e};return fault})
 if !errors.Is(e,fault){t.Fatal("fault not retained",e)}
 if _,e=s.ReadScopedFirstHeld(scope,intent);e!=nil{t.Fatal("sealed record lost",e)}
 if _,e=s.SealScopedFirstHeld(scope,intent);e==nil{t.Fatal("ambiguous seal replayed")}
 if _,e=s.Read();e==nil{t.Fatal("legacy admitted ambiguous seal")}
 t.Log("V2_FIRST_HELD_AMBIGUOUS_WRITE_STAYS_HELD=PASS")
}
