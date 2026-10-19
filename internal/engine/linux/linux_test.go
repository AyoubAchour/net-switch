//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

type byteCountingTun struct{ tun.Device }
func(*byteCountingTun)Write(p [][]byte,offset int)(int,error){return len(p[0])-offset+10,nil}
func TestLinuxTunWriteReturnsBytes(t *testing.T){
	d:=&Tun{device:&byteCountingTun{}}
	if err:=d.WritePacket(context.Background(),make([]byte,60));err!=nil{t.Fatalf("successful Linux TUN write must not terminate forwarding: %v",err)}
}

func TestDiagCookieAndCgroup(t *testing.T){
	b:=make([]byte,84);b[0]=unix.AF_INET
	binary.BigEndian.PutUint16(b[4:],1234);binary.BigEndian.PutUint16(b[6:],443)
	copy(b[8:],[]byte{192,0,2,1});copy(b[24:],[]byte{198,51,100,1})
	binary.NativeEndian.PutUint32(b[44:],0x12345678);binary.NativeEndian.PutUint32(b[48:],0x90abcdef)
	binary.NativeEndian.PutUint32(b[64:],1000);binary.NativeEndian.PutUint32(b[68:],42)
	binary.NativeEndian.PutUint16(b[72:],12);binary.NativeEndian.PutUint16(b[74:],21);binary.NativeEndian.PutUint64(b[76:],123456)
	r,err:=parseDiag(b);if err!=nil{t.Fatal(err)}
	if r.local!=netip.MustParseAddrPort("192.0.2.1:1234")||r.cookie!=0x90abcdef12345678||r.cgroup!=123456||r.inode!=42||r.uid!=1000{t.Fatalf("bad diag row: %+v",r)}
	binary.NativeEndian.PutUint16(b[72:],100);if _,err:=parseDiag(b);err==nil{t.Fatal("accepted truncated attribute")}
}

func TestRuleActionAndOneByteProtocol(t *testing.T){
	b:=make([]byte,20);b[0]=unix.AF_INET;b[4]=254;b[7]=1
	binary.NativeEndian.PutUint16(b[12:],5);binary.NativeEndian.PutUint16(b[14:],22);b[16]=17
	r,err:=parseRule(b);if err!=nil||r.rule.Type!=1||r.rule.Table!=254||r.rule.IPProto!=17||len(r.extra)!=0{t.Fatalf("UAPI rule: %+v %v",r,err)}
	b[7]=7;r,err=parseRule(b);if err!=nil||r.rule.Type!=7{t.Fatalf("action was lost: %+v %v",r,err)}
}

func TestRealUDPDiagAndConflictingLiveHolders(t *testing.T){
	c,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4zero});if err!=nil{t.Fatal(err)};defer c.Close()
	ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
	key:=c.LocalAddr().(*net.UDPAddr).AddrPort()
	rows,err:=diagDump(ctx,unix.AF_INET,unix.IPPROTO_UDP,key);if err!=nil{t.Fatal(err)}
	r,err:=matchUDP(rows,key);if err!=nil{t.Fatal(err)}
	if r.cookie==0||r.inode==0{t.Fatalf("socket lacks kernel identity: %+v",r)}
	o:=NewOwners()
	owner,err:=o.holders(ctx,r);if err!=nil||owner.PID!=uint32(os.Getpid())||owner.StartTime==0||owner.Generation==""{t.Fatalf("live owner: %+v %v",owner,err)}
	f,err:=c.File();if err!=nil{t.Fatal(err)};defer f.Close()
	child:=exec.Command("sleep","20");child.ExtraFiles=[]*os.File{f}
	if err:=child.Start();err!=nil{t.Fatal(err)}
	defer func(){child.Process.Kill();child.Wait()}()
	_,err=o.holders(ctx,r)
	if !errors.Is(err,platform.ErrAmbiguous){t.Fatalf("two real executable identities must be ambiguous, got %v",err)}
	child.Process.Kill();child.Wait()
	owner,err=o.holders(ctx,r);if err!=nil||owner.PID!=uint32(os.Getpid()){t.Fatalf("after other holder exits: %+v %v",owner,err)}
}

func TestUDPEndpointPreferenceAndAmbiguity(t *testing.T){
	key:=netip.MustParseAddrPort("198.18.0.1:12345")
	wild:=socketRow{local:netip.MustParseAddrPort("0.0.0.0:12345"),cookie:1}
	exact:=socketRow{local:key,cookie:2}
	r,err:=matchUDP([]socketRow{wild,exact},key);if err!=nil||r.cookie!=2{t.Fatalf("exact must win: %+v %v",r,err)}
	_,err=matchUDP([]socketRow{wild,wild},key);if !errors.Is(err,errSocketAmbiguous){t.Fatalf("wildcard reuse: %v",err)}
}

func TestOwnershipStoreTornTailAndCorruption(t *testing.T){
	path:=filepath.Join(t.TempDir(),"journal")
	s:=diskStore{path}
	r:=journal.Record{ID:"one",Boot:"boot",Instance:"instance",Kind:"route",Fingerprint:journal.Fingerprint{"table":"21001"},Phase:"intent"}
	if err:=s.Append(r);err!=nil{t.Fatal(err)}
	f,err:=os.OpenFile(path,os.O_APPEND|os.O_WRONLY,0);if err!=nil{t.Fatal(err)};f.WriteString("{\"record\":");f.Close()
	records,err:=s.Records();if err!=nil||len(records)!=1{t.Fatalf("torn tail recovery: %v %v",records,err)}
	r.Phase="created";if err:=s.Append(r);err!=nil{t.Fatal(err)}
	records,err=s.Records();if err!=nil||len(records)!=2{t.Fatalf("append after recovery: %v %v",records,err)}
	bad,_:=json.Marshal(diskRecord{json.RawMessage(`{"id":"bad"}`),"not a checksum"})
	f,_=os.OpenFile(path,os.O_APPEND|os.O_WRONLY,0);f.Write(append(bad,'\n'));f.Close()
	if _,err:=s.Records();err==nil{t.Fatal("complete corrupt record accepted")}
}

func TestLifetimeLockExcludesCleanup(t *testing.T){
	l:=fileLock{filepath.Join(t.TempDir(),"lock")}
	release,err:=l.Acquire(context.Background());if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Millisecond);defer cancel()
	if other,err:=l.Acquire(ctx);err==nil{other();t.Fatal("cleanup acquired a live engine's lock")}
	if err:=release();err!=nil{t.Fatal(err)}
	release,err=l.Acquire(context.Background());if err!=nil{t.Fatal(err)};release()
}

func TestLayoutMovesAsAWhole(t *testing.T){
	mask:=^uint32(0)
	rules:=[]netlink.Rule{{Priority:10001,Mark:0x4e530001,Mask:&mask,Table:21001}}
	if layoutAvailable(0,255,rules,nil){t.Fatal("accepted occupied priority/table/mark")}
	if !layoutAvailable(1000,255,rules,nil){t.Fatal("whole shifted layout unavailable")}
	mask=0xffff0000
	if layoutAvailable(1000,255,rules,nil){t.Fatal("ignored overlapping masked mark selector")}
}
