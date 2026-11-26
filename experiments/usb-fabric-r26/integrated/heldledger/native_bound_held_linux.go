//go:build linux

package heldledger

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "syscall"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/runtimeproof"
)

// NativeBoundVersion is a fail-closed, native-only HELD record. Legacy
// readers and scoped-v2 readers reject it. No clear or admission API exists.
const NativeBoundVersion = 3

type NativeHeldIdentity struct {
 Scope releasegate.Scope `json:"scope"`
 LaunchDigest string `json:"launch_digest"`
}

// NativeLaunchPin comes from protected host provisioning and current process
// incarnation observation, not the journal, guest stream or client. The old
// lease scope is recovered only from the protected durable record.
type NativeLaunchPin struct {
 GuestID string
 DeviceID string
 LaunchDigest string
}

type NativeHeldRecord struct {
 Version int `json:"version"`
 Sequence uint64 `json:"sequence"`
 Key string `json:"key"`
 Held bool `json:"held"`
 Identity NativeHeldIdentity `json:"native_identity"`
 LastReleaseEventSequence uint64 `json:"last_release_event_sequence,omitempty"`
 LastReleaseProofHash string `json:"last_release_proof_hash,omitempty"`
}

func strictNativeObject(raw []byte, value any) error {
 if e:=rejectDuplicateJournalKeys(raw);e!=nil{return ErrInvalid}
 d:=json.NewDecoder(bytes.NewReader(raw))
 d.DisallowUnknownFields()
 if e:=d.Decode(value);e!=nil{return ErrInvalid}
 var extra any
 if e:=d.Decode(&extra);e!=io.EOF{return ErrInvalid}
 return nil
}

func (id *NativeHeldIdentity) UnmarshalJSON(raw []byte)error{
 var wire struct{
  Scope json.RawMessage `json:"scope"`
  LaunchDigest string `json:"launch_digest"`
 }
 if e:=strictNativeObject(raw,&wire);e!=nil{return e}
 var scope releasegate.Scope
 if e:=strictNativeObject(wire.Scope,&scope);e!=nil{return e}
 *id=NativeHeldIdentity{Scope:scope,LaunchDigest:wire.LaunchDigest}
 return nil
}

func nativeLaunchDigest(s string)([32]byte,error){
 var out [32]byte
 if !validGenesisHex(s){return out,ErrInvalid}
 b,e:=hex.DecodeString(s)
 if e!=nil{return out,ErrInvalid}
 copy(out[:],b)
 if out==([32]byte{}){return out,ErrInvalid}
 return out,nil
}

func validateNativeHeld(r NativeHeldRecord,pin ed25519.PublicKey)error{
 if r.Version!=NativeBoundVersion||!r.Held||r.Key!=KeyA||r.Sequence==0||r.Sequence==^uint64(0)||
  len(pin)!=ed25519.PublicKeySize||bytes.Equal(pin,make([]byte,ed25519.PublicKeySize)){
  return ErrInvalid
 }
 s:=r.Identity.Scope
 if s.Generation==0||s.ReleaseSequence!=r.Sequence||s.GuestEpoch!=runtimeproof.InstanceEpoch(pin){return ErrInvalid}
 for _,v:=range []string{s.GuestID,s.DeviceID,s.HostEpoch,s.GuestEpoch,s.LeaseEpoch}{
  if len(v)==0||len(v)>256{return ErrInvalid}
  for _,c:=range v{if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'||c=='_'||c=='.'||c==':'||c=='/'){return ErrInvalid}}
 }
 if _,e:=nativeLaunchDigest(r.Identity.LaunchDigest);e!=nil{return e}
 if (r.LastReleaseEventSequence==0)!=(r.LastReleaseProofHash==""){return ErrInvalid}
 if r.LastReleaseProofHash!="" {
  b,e:=hex.DecodeString(r.LastReleaseProofHash)
  if e!=nil||len(b)!=32{return ErrInvalid}
 }
 return nil
}

// The caller must retain the original host owner and a stable, protected
// directory for the entire write/read/actuation transaction. This check is
// not a sandbox against the same UID or privileged host mutation.
func (s Store) nativeProtectedParent()error{
 if !filepath.IsAbs(s.Path)||filepath.Clean(s.Path)!=s.Path||filepath.Base(s.Path)=="."||filepath.Base(s.Path)=="/"{return ErrInvalid}
 dir:=filepath.Dir(s.Path)
 resolved,e:=filepath.EvalSymlinks(dir)
 if e!=nil||resolved!=dir{return ErrInvalid}
 info,e:=os.Lstat(dir)
 if e!=nil||!info.IsDir()||info.Mode().Perm()!=0700{return ErrInvalid}
 stat,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||stat.Uid!=uint32(os.Geteuid()){return ErrInvalid}
 return nil
}

// PersistNativeBoundHeld is an opt-in write-ahead transition in the ORIGINAL
// journal: exactly one v1 clean sequence becomes v3 HELD, atomically carrying
// the old lease and launch identity. It is not wired to the actuator yet.
// No legacy or v2 HELD/intent record is converted, no input is emitted, and
// no return value is permission to act. Any failed/ambiguous write must fence
// the current owner; the caller must never retry as though state were clean.
func(s Store)PersistNativeBoundHeld(expected uint64,id NativeHeldIdentity,pinned ed25519.PublicKey)(NativeHeldRecord,error){
 return s.persistNativeBoundHeld(expected,id,pinned,func(r NativeHeldRecord)error{return s.writeAtomicRecord(r)})
}

func(s Store)persistNativeBoundHeld(expected uint64,id NativeHeldIdentity,pinned ed25519.PublicKey,write func(NativeHeldRecord)error)(NativeHeldRecord,error){
 if e:=s.nativeProtectedParent();e!=nil{return NativeHeldRecord{},e}
 if write==nil||expected>=^uint64(0)-1{return NativeHeldRecord{},ErrInvalid}
 current,e:=s.Read()
 if e!=nil{return NativeHeldRecord{},e}
 if current.Sequence!=expected||current.Held||current.AdmissionIntent||current.ReleasePhase!=""{return NativeHeldRecord{},ErrConflict}
 r:=NativeHeldRecord{Version:NativeBoundVersion,Sequence:expected+1,Key:KeyA,Held:true,Identity:id,
  LastReleaseEventSequence:current.LastReleaseEventSequence,LastReleaseProofHash:current.LastReleaseProofHash}
 if e=validateNativeHeld(r,pinned);e!=nil{return NativeHeldRecord{},e}
 if e=write(r);e!=nil{return NativeHeldRecord{},fmt.Errorf("native bound write remains unavailable: %w",e)}
 return r,nil
}

// ReadNativeBoundHeld reads the old scope from the exact protected journal
// bytes, but independently supplied launch, guest, device and key must match.
// The digest is of the actual bytes read from the same descriptor, NOT a
// reserialization. This is observation only; no QMP, sensor, release or grant.
func(s Store)ReadNativeBoundHeld(expected NativeLaunchPin,pinned ed25519.PublicKey)(NativeHeldRecord,runtimeproof.RecoveryBinding,error){
 var r NativeHeldRecord
 var binding runtimeproof.RecoveryBinding
 if e:=s.nativeProtectedParent();e!=nil{return r,binding,e}
 raw,e:=s.readRawRecord()
 if e!=nil||raw==nil{
  if e==nil{e=ErrInvalid}
  return r,binding,e
 }
 if e=strictNativeObject(raw,&r);e!=nil{return NativeHeldRecord{},binding,e}
 if e=validateNativeHeld(r,pinned);e!=nil{return NativeHeldRecord{},binding,e}
 scope:=r.Identity.Scope
 if scope.GuestID!=expected.GuestID||scope.DeviceID!=expected.DeviceID||r.Identity.LaunchDigest!=expected.LaunchDigest{
  return NativeHeldRecord{},binding,ErrUnverified
 }
 launch,e:=nativeLaunchDigest(r.Identity.LaunchDigest)
 if e!=nil{return NativeHeldRecord{},binding,e}
 binding=runtimeproof.RecoveryBinding{Scope:scope,LaunchDigest:launch,HeldDigest:sha256.Sum256(raw)}
 return r,binding,nil
}
