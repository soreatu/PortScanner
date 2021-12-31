package scanner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"portscanner/internal/log"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var UDPPayload = [7]byte{'w', 'h', 'o', 'a', 'm', 'i', '\n'}
var ICMPPayload = [11]byte{'P', 'o', 'r', 't', 'S', 'c', 'a', 'n', 'n', 'e', 'r'}

// ScanTCP 对传入的所有端口进行TCP扫描，并根据扫描结果设置端口的Status
func ScanTCP(tuples []Tuple) []Tuple {
	wg := sync.WaitGroup{}

	// 多线程发送TCP-SYN包
	for i := range tuples {
		wg.Add(1)
		go scanTCP(&tuples[i], &wg)
	}

	wg.Wait()
	return tuples
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

// scanTCP 向目标端口发起TCP三次握手，若握手成功，则设置端口状态为OPEN
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

// scanUDP 向目标端口发送一个UDP数据包，若目标端口有回应UDP数据包，则设置端口状态为OPEN
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

	buff := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
	// block直至读取到回包
	n, err := conn.Read(buff)
	if err != nil {
		log.Log().Debug("failed to read (udp) from %s: %s", t, err.Error())
		return
	}
	// 有回包，设置为OPEN
	log.Log().Info("read %s from <%s>", buff[:n], conn.RemoteAddr())
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
