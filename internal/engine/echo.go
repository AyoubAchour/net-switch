package engine

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type echoes struct { ctx context.Context; dial platform.Echoer; table *flows.Table; out flowapi.Output; slots chan struct{}; workers sync.WaitGroup }
func newEcho(ctx context.Context,d platform.LineDialer,t *flows.Table,out flowapi.Output)*echoes{dial,_:=d.(platform.Echoer);return &echoes{ctx:ctx,dial:dial,table:t,out:out,slots:make(chan struct{},64)}}
func(e *echoes)wait(){e.workers.Wait()}
func(e *echoes)handle(b []byte)bool{
	if e.dial==nil{return false}
	var src,dst netip.Addr;var body []byte;var proto byte
	if len(b)>=28&&b[0]>>4==4&&b[9]==1{
		h:=int(b[0]&15)*4
		if h<20||len(b)<h+8||b[h]!=8{return false}
		if binary.BigEndian.Uint16(b[6:])&0x3fff!=0{return true}
		src=netip.AddrFrom4([4]byte(b[12:16]));dst=netip.AddrFrom4([4]byte(b[16:20]));body=b[h:];proto=1
		if packet.Sum(b[:h],0)!=65535||packet.Sum(body,0)!=65535{return true}
	}else if len(b)>=48&&b[0]>>4==6&&b[6]==58&&b[40]==128{
		src=netip.AddrFrom16([16]byte(b[8:24]));dst=netip.AddrFrom16([16]byte(b[24:40]));body=b[40:];proto=58
		if packet.Sum(body,packet.Pseudo(src,dst,proto,len(body)))!=65535{return true}
	}else{return false}
	if body[1]!=0{return true}
	line,err:=e.table.EchoLine(src.Is6());if err!=nil{return true}
	select{case e.slots<-struct{}{}:default:return true}
	request:=append([]byte(nil),body...)
	e.workers.Go(func(){
		defer func(){<-e.slots}()
		ctx,cancel:=context.WithTimeout(e.ctx,3*time.Second);defer cancel()
		reply,err:=e.dial.Echo(ctx,line,dst,request);if err!=nil||len(reply)<8{return}
		copy(reply[4:8],request[4:8]);reply[2],reply[3]=0,0
		initial:=uint32(0);if proto==58{initial=packet.Pseudo(dst,src,proto,len(reply))}
		binary.BigEndian.PutUint16(reply[2:],^packet.Sum(reply,initial))
		e.out.Send(packet.IP(dst,src,proto,reply))
	})
	return true
}
