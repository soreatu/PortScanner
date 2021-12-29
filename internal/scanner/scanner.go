package scanner

import (
	"fmt"
	"net"
	"portscanner/internal/log"
	"sync"
	"time"
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
				fmt.Sprintf("%s:%v", t.IP.String(), t.Port),
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
	// TODO: implement
	return nil
}
