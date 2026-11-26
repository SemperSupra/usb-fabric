package runtimeproof

import (
 "crypto/ed25519"
 "crypto/rand"
 "testing"
 releasegate "example.org/usb-fabric-r26-releasegate"
)
func TestProtectedInstanceEnrollment(t *testing.T){
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 other,foreign,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 if InstanceEpoch(pub)==InstanceEpoch(other)||InstanceEpoch(nil)!=""{t.Fatal("bad epoch")}
 scope:=releasegate.Scope{GuestID:"guest",DeviceID:"kbd",HostEpoch:"host",GuestEpoch:InstanceEpoch(pub),LeaseEpoch:"lease",Generation:1,ReleaseSequence:1}
 nonce,e:=NewHostChallenge();if e!=nil{t.Fatal(e)}
 a,e:=NewAuthority(pub,scope,nonce);if e!=nil{t.Fatal(e)}
 w:=Event{Scope:scope,Challenge:nonce,Source:"guest.enrollment",KeyCode:"instance",EventSequence:1}
 if a.Enrolled(){t.Fatal("enrolled before proof")}
 bad,e:=Sign(foreign,w);if e!=nil{t.Fatal(e)}
 if a.ConfirmEnrollment(bad)==nil||a.Enrolled(){t.Fatal("foreign key accepted")}
 wrongNonce:=w;wrongNonce.Challenge[0]^=1
 bad,e=Sign(priv,wrongNonce);if e!=nil{t.Fatal(e)}
 if a.ConfirmEnrollment(bad)==nil{t.Fatal("stale challenge accepted")}
 good,e:=Sign(priv,w);if e!=nil{t.Fatal(e)}
 if e=a.ConfirmEnrollment(good);e!=nil||!a.Enrolled(){t.Fatal("valid enrollment denied",e)}
 if a.ConfirmEnrollment(good)==nil||a.Reclaimable(){t.Fatal("replay or release overclaim")}
 next:=scope;next.Generation++
 b,e:=NewAuthority(pub,next,nonce);if e!=nil{t.Fatal(e)}
 if b.ConfirmEnrollment(good)==nil||b.Enrolled(){t.Fatal("prior lease proof accepted")}
 t.Log("PROTECTED_INSTANCE_ENROLLMENT_FOREIGN_REPLAY_RELEASE_DENIED=PASS")
}
