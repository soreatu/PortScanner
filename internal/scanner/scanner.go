package scanner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/phayes/freeport"
	"golang.org/x/net/ipv4"
	"net"
	"portscanner/internal/log"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

var UDPPayload = [3]byte{'l', 's', '\n'}
var ICMPPayload = [11]byte{'P', 'o', 'r', 't', 'S', 'c', 'a', 'n', 'n', 'e', 'r'}

// ScanTCP 对传入的所有端口进行TCP扫描，并根据扫描结果设置端口的Status
func ScanTCP(tuples []Tuple) []Tuple {
	wg := sync.WaitGroup{}
	// 多线程发送TCP-SYN包
	for i := range tuples {
		wg.Add(1)
		conn, _ := net.Dial("tcp", fmt.Sprintf("%s:%d", tuples[i].IP, tuples[i].Port))
		conn.Close()
		//go scanTCPSYN(i, &tuples[i], &wg)
	}

	wg.Wait()
	return tuples
}

// scanTCPSYN 向目标地址发送一个TCP-SYN请求包
func scanTCPSYN(i int, t *Tuple, wg *sync.WaitGroup) {
	defer wg.Done()

	// 组建tcp header
	srcPort, err := freeport.GetFreePort()
	if err != nil {
		log.Log().Error("failed to get a free port: %s", srcPort)
		return
	}

	//tcp := header.TCP(make([]byte, 20))
	//fields := header.TCPFields{
	//	SrcPort:       uint16(srcPort),
	//	DstPort:       uint16(t.Port),
	//	SeqNum:        uint32(0xdeadbeaf + i),
	//	AckNum:        0,
	//	DataOffset:    20, // 20 bytes
	//	Flags:         header.TCPFlagSyn,
	//	WindowSize:    65535,
	//	Checksum:      0,
	//	UrgentPointer: 0,
	//}
	//tcp.Encode(&fields)
	header := &TCPHeader{
		Source:      uint16(srcPort),
		Destination: uint16(t.Port),
		SeqNum:      uint32(0xdeadbeaf + i),
		AckNum:      0,
		DataOffset:  5,
		Reserved:    0,
		ECN:         0,
		Ctrl:        SYN,
		Window:      65535,
		Urgent:      0,
		Options:     []TCPOption{},
	}
	tcp := header.Marshal()

	// 开3层连接
	ipConn, err := net.DialIP("ip4:tcp", nil, &net.IPAddr{IP: t.IP})
	if err != nil {
		log.Log().Error("failed to dial ip: %s", err.Error())
		return
	}

	header.Checksum = Checksum(tcp, ipConn.LocalAddr().(*net.IPAddr).IP, t.IP)
	tcp = header.Marshal()
	log.Log().Info("Sending data: %v", tcp)

	// 发TCP-SYN包
	_, err = ipConn.Write(tcp)
	if err != nil {
		log.Log().Error("failed to write to ipConn: %s", err.Error())
		return
	}

	buff := make([]byte, 1024)
	_ = ipConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	// 接受回包
	n, err := ipConn.Read(buff)
	if err != nil {
		// timeout + icmp unreachable => FILTER
		log.Log().Info("read from ipConn error: %s", err.Error())
		t.SetFilter()
		return
	}
	log.Log().Info("read from ipConn: %v", buff[:n])

	// 解析数据段
	recv := NewTCPHeader(buff)
	// SYN-ACK => OPEN
	// RST => CLOSE
	if recv.HasFlag(SYN) && recv.HasFlag(ACK) {
		log.Log().Info("target %s responded with SYN+ACK", t.IP)
		t.SetOpen()
	} else if recv.HasFlag(RST) {
		log.Log().Info("target %s responded with RST", t.IP)
	}
}

// ScanUDP 对传入的所有端口进行UDP扫描，并根据扫描结果设置端口的Status
func ScanUDP(tuples []Tuple) []Tuple {
	wg := sync.WaitGroup{}
	// 多线程发送UDP包
	for i := range tuples {
		wg.Add(1)
		go scanUDP(&tuples[i], &wg)
	}

	wg.Wait()
	return tuples
}

// scanUDP 向目标发送一个UDP请求包
func scanUDP(t *Tuple, wg *sync.WaitGroup) {
	defer wg.Done()

	// 建立udp连接
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: t.IP, Port: t.Port})
	if err != nil {
		log.Log().Debug("failed to dial (udp) %s: %s\n", t, err.Error())
		return
	}
	defer conn.Close()

	// 发数据包
	_, err = conn.Write(UDPPayload[:])
	if err != nil {
		log.Log().Debug("failed to write (udp) %s: %s\n", t, err.Error())
		return
	}

	// OPEN: 有UDP回包
	// FILTER: 超时
	// CLOSE: 返回icmp port unreachable报文

	buff := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	// block直至读取到回包
	n, err := conn.Read(buff)
	if err != nil {
		log.Log().Debug("failed to read (udp) from %s: %s", t, err.Error())
		if err.(*net.OpError).Timeout() {
			// 超时，设置为FILTER
			log.Log().Info("reading timed out, set FILTER on %s", conn.RemoteAddr())
			t.SetFilter()
		}
		// 否则，默认为CLOSE
		return
	}
	// 有回包，设置为OPEN
	log.Log().Info("read %s from <%s>", buff[:n], conn.RemoteAddr())
	t.SetOpen()
}

// ScanICMP 对传入的所有端口进行ICMP扫描，并根据扫描结果设置端口的Status
func ScanICMP(tuples []Tuple) []Tuple {
	// 多线程发送ICMP echo请求包
	for i := range tuples {
		go sendICMP(i, &tuples[i])
	}

	done := make(chan error, 1)
	go func() {
		// 开监听
		conn, err := net.ListenIP("ip4:icmp", nil)
		if err != nil {
			log.Log().Error("failed to call ListenIP, error: %s", err.Error())
			done <- err
			return
		}
		defer conn.Close()

		for {
			buff := make([]byte, 1024)
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

			// block直至接受到回包，或者超时
			n, ra, err := conn.ReadFrom(buff)
			if err != nil {
				log.Log().Error("failed to read ICMP packet: %s", err.Error())
				done <- err
				return
			}
			go receiveICMP(ra, buff[:n], &tuples)
		}
	}()

	select {
	case err := <-done:
		log.Log().Error("error: %s", err.Error())
	case <-time.After(3 * time.Second):
		log.Log().Info("waiting times out")
	}

	return tuples
}

func scanTCP(t *Tuple, wg *sync.WaitGroup) {
	defer wg.Done()

	// 发起TCP三次握手
	conn, err := net.DialTimeout(
		"tcp4",
		fmt.Sprintf("%s:%v", t.IP, t.Port),
		500*time.Millisecond,
	)
	if err != nil || conn == nil {
		log.Log().Debug("failed to dial (tcp) %s: %s\n", t.String(), err.Error())
		return
	}
	defer conn.Close()

	t.SetOpen()
}

// sendICMP 组装ICMP请求包，并向目标端口发送
func sendICMP(i int, t *Tuple) {
	// 组建ICMP请求包
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x23333,
			Seq:  i,
			Data: ICMPPayload[:],
		},
	}
	buff, _ := msg.Marshal(nil)

	// 发送给目标端口
	log.Log().Info("sending ICMP packet to %s", t.IP)
	conn, err := net.Dial("ip4:icmp", t.IP.String())
	if err != nil {
		log.Log().Error("failed to dial %s, error: %s", t.IP, err.Error())
		return
	}
	defer conn.Close()

	_, err = conn.Write(buff)
	if err != nil {
		log.Log().Error("failed to send ICMP packet to %s, error: %s", t.IP, err.Error())
		return
	}
}

// receiveICMP 解析ICMP回包，并根据回包类型设置对应的Tuple状态
func receiveICMP(ra net.Addr, buff []byte, tuples *[]Tuple) {
	log.Log().Info("receiving reply packet data: %s", hex.EncodeToString(buff))

	// 解析回包
	msg, err := icmp.ParseMessage(1, buff)
	if err != nil {
		log.Log().Error("failed to parse message: %s", err.Error())
		return
	}
	log.Log().Info("parsed icmp message: %v %v", msg.Type, msg.Body)

	// 反射为Echo类型
	body, ok := msg.Body.(*icmp.Echo)
	if !ok {
		log.Log().Error("message type is not echo")
		return
	}
	// 校验数据段
	if bytes.Compare(body.Data, ICMPPayload[:]) != 0 {
		log.Log().Error("message data does not match")
		return
	}
	// 提取序列号并校验
	seq := body.Seq
	if seq < 0 || len(*tuples) <= seq {
		log.Log().Info("sequence number out of bound: %d", seq)
		return
	}
	// 校验ip地址
	if (*tuples)[seq].IP.String() != ra.String() {
		log.Log().Info("IP address %s does not match %s", (*tuples)[seq].IP, ra)
		return
	}
	// 设置Status为OPEN
	(*tuples)[seq].SetOpen()
}
