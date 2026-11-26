//go:build linux

package main

import (
 "crypto/ed25519"
 "errors"
 "io"
 "os"
 "path/filepath"
 "syscall"
)

// Only a trusted service account can provision this pin. Do not learn the
// key from the receipt stream, client request or a shared pathname.
func readProtectedGuestPin(path string)([]byte,error){
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path{return nil,errors.New("noncanonical guest pin")}
 dir,err:=syscall.Open(filepath.Dir(path),syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,err}
 defer syscall.Close(dir)
 var st syscall.Stat_t
 if err=syscall.Fstat(dir,&st);err!=nil{return nil,err}
 if st.Uid!=uint32(os.Geteuid())||st.Mode&0777!=0700{return nil,errors.New("guest pin parent not private")}
 fd,err:=syscall.Openat(dir,filepath.Base(path),syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,err}
 file:=os.NewFile(uintptr(fd),path)
 if file==nil{_ = syscall.Close(fd);return nil,errors.New("invalid pin descriptor")}
 defer file.Close()
 if err=syscall.Fstat(fd,&st);err!=nil{return nil,err}
 if st.Uid!=uint32(os.Geteuid())||st.Mode&syscall.S_IFMT!=syscall.S_IFREG||
  st.Mode&0222!=0||st.Size!=ed25519.PublicKeySize{return nil,errors.New("guest pin not immutable private-owner file")}
 b,err:=io.ReadAll(io.LimitReader(file,ed25519.PublicKeySize+1))
 if err!=nil||len(b)!=ed25519.PublicKeySize{return nil,errors.New("guest pin wrong length")}
 return b,nil
}
