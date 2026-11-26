//go:build linux

package blue

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "strings"
 "sync"
 "sync/atomic"
 "testing"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

func firstHeldFixture(t *testing.T)(*ScopedGenesisOwner,heldledger.GenesisScope,heldledger.Store,heldledger.State){
 t.Helper()
 scope,store:=scopedOwnerFixture(t)
 o,e:=OpenScopedGenesisOwner(scope,store);if e!=nil{t.Fatal(e)}
 t.Cleanup(func(){_ = o.Close()})
 st,e:=o.CreateHeldGenesis();if e!=nil{t.Fatal(e)}
 if _,e=o.SealFirstHeld();!errors.Is(e,ErrQuarantined){t.Fatal("unprepared seal accepted",e)}
 op:=strings.Repeat("ab",32)
 pins:=map[string]ed25519.PublicKey{}
 var ws []heldledger.GenesisWitness
 for domain,obs:=range map[string]string{"host-actuator":"OLD_ACCESS_FENCED","usbip-exporter":"OLD_EXPORT_DENIED","linux-vhci":"OLD_IMPORT_ABSENT","network-effective-deny":"OLD_SESSIONS_DENIED","guest-input-release":"NEUTRAL_INPUT_OBSERVED"}{
  pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  w:=heldledger.GenesisWitness{Domain:domain,Scope:scope,Nonce:st.GenesisNonce,Operation:op,Observation:obs}
  b,e:=w.SigningBytes();if e!=nil{t.Fatal(e)}
  w.Signature=ed25519.Sign(priv,b);pins[domain]=pub;ws=append(ws,w)
 }
 intent,e:=o.PrepareAdmission(op,ws,pins);if e!=nil{t.Fatal(e)}
 return o,scope,store,intent
}

func TestScopedFirstHeldSameOwnerCopies(t *testing.T){
 o,scope,store,intent:=firstHeldFixture(t)
 expected:=intent;scopeCopy:=scope;expected.Scope=&scopeCopy
 intent.Scope.DeviceResource="caller-mutated"
 copyOwner:=*o
 var success atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<32;i++{
  wg.Add(1);go func(){defer wg.Done();c:=copyOwner
   if _,e:=c.SealFirstHeld();e==nil{success.Add(1)}
  }()
 }
 wg.Wait()
 if success.Load()!=1{t.Fatal("seal consumption count",success.Load())}
 if _,e:=store.ReadScopedFirstHeld(scope,expected);e!=nil{t.Fatal("bad seal",e)}
 if e:=copyOwner.Close();e!=nil{t.Fatal(e)}
 if _,e:=o.SealFirstHeld();!errors.Is(e,ErrQuarantined){t.Fatal("owner copy survived close",e)}
 other,e:=OpenScopedGenesisOwner(scope,store);if e!=nil{t.Fatal(e)}
 defer other.Close()
 if _,e=other.SealFirstHeld();!errors.Is(e,ErrQuarantined){t.Fatal("new owner reconstructed seal",e)}
 t.Log("V2_FIRST_HELD_OWNER_COPY_ONE_SHOT=PASS")
}

func TestScopedFirstHeldRestartDeniesIntentReplay(t *testing.T){
 o,scope,store,_:=firstHeldFixture(t)
 before,e:=os.ReadFile(store.Path);if e!=nil{t.Fatal(e)}
 alias:=*o
 if e=alias.Close();e!=nil{t.Fatal(e)}
 other,e:=OpenScopedGenesisOwner(scope,store);if e!=nil{t.Fatal(e)}
 defer other.Close()
 if _,e=other.SealFirstHeld();!errors.Is(e,ErrQuarantined){t.Fatal("reconstructed old intent",e)}
 if _,e=o.SealFirstHeld();!errors.Is(e,ErrQuarantined){t.Fatal("old owner accepted",e)}
 after,e:=os.ReadFile(store.Path);if e!=nil||!bytes.Equal(before,after){t.Fatal("replay mutated journal",e)}
 t.Log("V2_FIRST_HELD_REOPENED_INTENT_REPLAY_DENIED=PASS")
}

func TestScopedFirstHeldStaleDiskConsumesAttempt(t *testing.T){
 o,_,store,_:=firstHeldFixture(t)
 original,e:=os.ReadFile(store.Path);if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(store.Path,[]byte("{}\n"),0600);e!=nil{t.Fatal(e)}
 if _,e=o.SealFirstHeld();e==nil{t.Fatal("corrupt state accepted")}
 if e=os.WriteFile(store.Path,original,0600);e!=nil{t.Fatal(e)}
 if _,e=o.SealFirstHeld();!errors.Is(e,ErrQuarantined){t.Fatal("failed seal retried",e)}
 after,e:=os.ReadFile(store.Path);if e!=nil||!bytes.Equal(original,after){t.Fatal("denied seal changed restored intent",e)}
 t.Log("V2_FIRST_HELD_FAILED_ATTEMPT_TERMINAL=PASS")
}
