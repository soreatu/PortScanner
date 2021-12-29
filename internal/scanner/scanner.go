package scanner

import (
	"fmt"
	"golang.org/x/net/ipv4"
	"net"
	"portscanner/internal/log"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

// ScanTCP 对传入的所有端口进行TCP扫描，并根据扫描结果设置端口的Status
func ScanTCP(tuples []Tuple) []Tuple {
	wg := sync.WaitGroup{}
	wg.Add(len(tuples))

	// 多线程逐一扫描
	for i := range tuples {
		tuple := &tuples[i]
		go func(t *Tuple) {
			conn, err := net.DialTimeout(
				"tcp4",
				fmt.Sprintf("%s:%v", t.IP, t.Port),
				500*time.Millisecond,
			)
			if err != nil || conn == nil {
				log.Log().Debug("dialling got error: %s when dialling %s\n", t.String(), err.Error())
				fmt.Printf("[+] %s is CLOSE\n", t.String())
			} else {
				t.SetOpen()
				fmt.Printf("[+] %s is OPEN\n", t.String())
				conn.Close()
			}
			wg.Done()
		}(tuple)
	}

	wg.Wait()

	return tuples
}

// ScanUDP 对传入的所有端口进行UDP扫描，并根据扫描结果设置端口的Status
func ScanUDP(tuples []Tuple) []Tuple {
	// TODO: implement
	return nil
}

// ScanICMP 对传入的所有端口进行ICMP扫描，并根据扫描结果设置端口的Status
func ScanICMP(tuples []Tuple) []Tuple {
	// 读取超时
	timeout := 5 * time.Second

	conn, err := net.ListenIP("ip:icmp", nil)
	if err != nil {
		log.Log().Error("calling ListenIP failed: %s", err.Error())
	}
	defer conn.Close()
	//conn.SetReadDeadline()

	// 多线程发包
	for i, t := range tuples {
		go sendICMPData(conn, i, t)
	}

	// 收包，解析包，并设置状态
	done := make(chan error, 1)
	go func() {
		for {
			buff := make([]byte, 256)
			n, ra, err := conn.ReadFrom(buff)
			if err != nil {
				done <- err
				return
			}
			go receiveICMPData(&tuples, ra, buff[:n])
		}
	}()

	select {
	case err := <-done:
		log.Log().Error("failed to read from connection: %s", err.Error())
		return nil
	case <-time.After(timeout):
		log.Log().Info("trying to read from connection timed out")
	}

	return tuples
}

// sendICMPData 组装ICMP请求包，并向目标端口发送
func sendICMPData(conn *net.IPConn, i int, t Tuple) {
	log.Log().Info("sending ICMP packet to %s:%v", t.IP, t.Port)

	// 组建UDP请求包
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x23333,
			Seq:  i,
			Data: []byte{0x50, 0x6f, 0x72, 0x74, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72},
		},
	}
	buff, _ := msg.Marshal(nil)

	// 发送给目标端口
	_, err := conn.WriteTo(buff, &net.UDPAddr{IP: t.IP})
	if err != nil {
		log.Log().Error("failed to send ICMP packet to %s:%v", t.IP, t.Port)
	}
}

// receiveICMPData 解析ICMP响应包，并设置状态
func receiveICMPData(tuples *[]Tuple, ra net.Addr, buff []byte) {
	// 解析message
	msg, err := icmp.ParseMessage(1, buff)
	if err != nil {
		log.Log().Error("failed to parse icmp message: %s", err.Error())
		return
	}

	reply, ok := msg.Body.(*icmp.Echo)
	if !ok {
		log.Log().Error("not echo reply: %s")
		return
	}
	// 取序列号
	seq := reply.Seq
	if seq < 0 || seq > len(*tuples) {
		log.Log().Error("echo reply sequence out of range: %d", seq)
		return
	}
	// 设置状态为OPEN
	(*tuples)[seq].SetOpen()
	//if t.IP.String() != ra.String() {
	//
	//}
}
