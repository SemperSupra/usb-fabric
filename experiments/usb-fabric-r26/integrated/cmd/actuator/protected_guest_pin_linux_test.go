//go:build linux

package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "os"
 "path/filepath"
 "testing"
)
func TestProtectedGuestPinOwnershipAndMode(t *testing.T){
 dir:=t.TempDir();if e:=os.Chmod(dir,0700);e!=nil{t.Fatal(e)}
 pub,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 p:=filepath.Join(dir,"pin")
 if e=os.WriteFile(p,pub,0400);e!=nil{t.Fatal(e)}
 if b,e:=readProtectedGuestPin(p);e!=nil||string(b)!=string(pub){t.Fatal("pin denied",e)}
 if e=os.Chmod(p,0600);e!=nil{t.Fatal(e)}
 if _,e=readProtectedGuestPin(p);e==nil{t.Fatal("writable pin accepted")}
 if e=os.Chmod(p,0400);e!=nil{t.Fatal(e)}
 link:=filepath.Join(dir,"link")
 if e=os.Symlink(p,link);e!=nil{t.Fatal(e)}
 if _,e=readProtectedGuestPin(link);e==nil{t.Fatal("symlink pin accepted")}
 if e=os.Chmod(dir,0755);e!=nil{t.Fatal(e)}
 if _,e=readProtectedGuestPin(p);e==nil{t.Fatal("unprotected parent accepted")}
 t.Log("PROTECTED_GUEST_PIN_PRIVATE_READONLY_NOFOLLOW=PASS")
}
