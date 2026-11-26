//go:build linux

package blue

// This is a real kernel TCP witness experiment, not a production network
// adapter. The child owns the disposable old transport; the observer holds
// the original scoped resource owner and its own test signing key. Four
// remaining witness domains are fixtures, so this test never proves G4.
import (
 "bufio"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "os/exec"
 "strings"
 "syscall"
 "testing"
 "time"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

func tcpFixtureChild(t *testing.T){
 l,e:=net.Listen("tcp4","127.0.0.1:0");if e!=nil{t.Fatal(e)}
 defer l.Close()
 fmt.Println("READY "+l.Addr().String())
 c,e:=l.Accept();if e!=nil{t.Fatal(e)}
 defer c.Close()
 done:=make(chan struct{})
 go func(){
  defer close(done)
  s:=bufio.NewScanner(c)
  for s.Scan(){
   if _,e:=fmt.Fprintln(c,"ACK "+s.Text());e!=nil{return}
  }
 }()
 s:=bufio.NewScanner(os.Stdin)
 for s.Scan(){
  switch s.Text(){
  case "close-listener":
   if e:=l.Close();e!=nil{t.Fatal(e)}
   fmt.Println("LISTENER_CLOSED")
  case "fence":
   if e:=c.Close();e!=nil{t.Fatal(e)}
   <-done
   fmt.Println("SESSION_CLOSED")
  case "stop":return
  default:t.Fatal("bad control")
  }
 }
}
func tcpEcho(c net.Conn,request string)(string,error){
 if e:=c.SetDeadline(time.Now().Add(2*time.Second));e!=nil{return "",e}
 if _,e:=fmt.Fprintln(c,request);e!=nil{return "",e}
 line,e:=bufio.NewReader(c).ReadString('\n')
 return strings.TrimSpace(line),e
}
func terminalTCPError(e error)bool{
 return errors.Is(e,io.EOF)||errors.Is(e,syscall.ECONNRESET)||errors.Is(e,syscall.EPIPE)
}
// A timeout is NOT evidence of effective denial. Require the known old
// session to terminate and a fresh connection to the known endpoint to be
// refused. This observes a point in time on the isolated loopback lane;
// the caller must keep the external fence effective through durable commit.
func observeDeniedTCP(old net.Conn,addr string)error{
 _,e:=tcpEcho(old,"old-generation-request")
 if !terminalTCPError(e){return fmt.Errorf("old session not proven denied: %v",e)}
 c,e:=net.DialTimeout("tcp4",addr,time.Second)
 if e==nil{_ = c.Close();return errors.New("old endpoint still accepts new connections")}
 if !errors.Is(e,syscall.ECONNREFUSED){return fmt.Errorf("new connect not definitively refused: %v",e)}
 return nil
}
func signScopedFixture(t *testing.T,scope heldledger.GenesisScope,nonce,op,domain,obs string,priv ed25519.PrivateKey)heldledger.GenesisWitness{
 t.Helper()
 w:=heldledger.GenesisWitness{Domain:domain,Scope:scope,Nonce:nonce,Operation:op,Observation:obs}
 b,e:=w.SigningBytes();if e!=nil{t.Fatal(e)}
 w.Signature=ed25519.Sign(priv,b)
 return w
}
func TestScopedOwnerLiveTCPWitness(t *testing.T){
 if os.Getenv("USB_SCOPED_TCP_CHILD")=="1"{tcpFixtureChild(t);return}
 scope,store:=scopedOwnerFixture(t)
 owner,e:=OpenScopedGenesisOwner(scope,store);if e!=nil{t.Fatal(e)}
 defer owner.Close()
 st,e:=owner.CreateHeldGenesis();if e!=nil{t.Fatal(e)}
 before,e:=os.ReadFile(store.Path);if e!=nil{t.Fatal(e)}
 var opBytes [32]byte
 if _,e=rand.Read(opBytes[:]);e!=nil{t.Fatal(e)}
 op:=hex.EncodeToString(opBytes[:])
 ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestScopedOwnerLiveTCPWitness$")
 cmd.Env=append(os.Environ(),"USB_SCOPED_TCP_CHILD=1")
 out,e:=cmd.StdoutPipe();if e!=nil{t.Fatal(e)}
 in,e:=cmd.StdinPipe();if e!=nil{t.Fatal(e)}
 cmd.Stderr=os.Stderr
 if e=cmd.Start();e!=nil{t.Fatal(e)}
 defer func(){_ = cmd.Process.Kill();_ = cmd.Wait()}()
 rd:=bufio.NewReader(out)
 line,e:=rd.ReadString('\n');if e!=nil||!strings.HasPrefix(line,"READY 127.0.0.1:"){t.Fatalf("child ready: %q %v",line,e)}
 addr:=strings.TrimSpace(strings.TrimPrefix(line,"READY "))
 c,e:=net.DialTimeout("tcp4",addr,time.Second);if e!=nil{t.Fatal(e)}
 defer c.Close()
 if got,e:=tcpEcho(c,"old-live");e!=nil||got!="ACK old-live"{t.Fatal("baseline TCP not effective",got,e)}
 send:=func(command,want string){
  t.Helper()
  if _,e:=fmt.Fprintln(in,command);e!=nil{t.Fatal(e)}
  line,e:=rd.ReadString('\n')
  if e!=nil||strings.TrimSpace(line)!=want{t.Fatalf("child %s: %q %v",command,line,e)}
 }
 pins:=map[string]ed25519.PublicKey{}
 var ws []heldledger.GenesisWitness
 for domain,obs:=range map[string]string{
  "host-actuator":"OLD_ACCESS_FENCED","usbip-exporter":"OLD_EXPORT_DENIED",
  "linux-vhci":"OLD_IMPORT_ABSENT","guest-input-release":"NEUTRAL_INPUT_OBSERVED",
 }{
  pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  pins[domain]=pub;ws=append(ws,signScopedFixture(t,scope,st.GenesisNonce,op,domain,obs,priv))
 }
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 pins["network-effective-deny"]=pub
 send("close-listener","LISTENER_CLOSED")
 if e=observeDeniedTCP(c,addr);e==nil{t.Fatal("listener-only closure falsely accepted")}
 if _,e=owner.PrepareAdmission(op,ws,pins);e==nil{t.Fatal("incomplete proof committed")}
 after,e:=os.ReadFile(store.Path);if e!=nil||string(before)!=string(after){t.Fatal("negative changed HELD")}
 t.Log("LIVE_TCP_LISTENER_ONLY_OLD_SESSION_STILL_EFFECTIVE_DENIED=PASS")
 send("fence","SESSION_CLOSED")
 if e=observeDeniedTCP(c,addr);e!=nil{t.Fatal(e)}
 t.Log("LIVE_TCP_OLD_SESSION_TERMINAL_AND_NEW_CONNECT_REFUSED=PASS")
 w:=signScopedFixture(t,scope,st.GenesisNonce,op,"network-effective-deny","OLD_SESSIONS_DENIED",priv)
 ws=append(ws,w)
 if _,e=owner.PrepareAdmission(strings.Repeat("cd",32),ws,pins);e==nil{t.Fatal("foreign operation witness accepted")}
 intent,e:=owner.PrepareAdmission(op,ws,pins)
 if e!=nil||!intent.AdmissionIntent||intent.Held{t.Fatalf("intent: %+v %v",intent,e)}
 if _,e=owner.PrepareAdmission(op,ws,pins);e==nil{t.Fatal("replay accepted")}
 if m,old,e:=NewAfterExclusiveDurableAdmission(scope.DeviceResource,scope.DownstreamPort,nil,store);e==nil||old!=nil{
  if old!=nil{_ = old.Close()};t.Fatalf("legacy manager accepted scoped intent: %v",m)
 }
 if e=observeDeniedTCP(c,addr);e!=nil{t.Fatal("network fence lost at commit",e)}
 if _,e=fmt.Fprintln(in,"stop");e!=nil{t.Fatal(e)}
 _=in.Close()
 if e=cmd.Wait();e!=nil{t.Fatal(e)}
 t.Log("LIVE_TCP_WITNESS_SCOPED_INTENT_NO_GRANT=PASS")
 t.Log("OTHER_FOUR_WITNESSES_FIXTURE_ONLY_LIVE_USBIP_G4_NOT_TESTED")
}
