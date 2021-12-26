package scanner

import (
	"fmt"
	"net"
	"portscanner/internal/log"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// Scan 对传入的所有端口进行扫描，并根据扫描结果设置端口的Status
func Scan(tuples []Tuple) []Tuple {
	wg := sync.WaitGroup{}
	wg.Add(len(tuples))

	// 多线程逐一扫描
	for i := range tuples {
		tuple := &tuples[i]
		go func(t *Tuple) {
			conn, err := Dial(*t)
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

// Dial 向目标端口发起连接请求，如果目标端口回应就返回一个net.Conn对象，否则返回error
func Dial(t Tuple) (conn net.Conn, err error) {
	d := net.Dialer{Timeout: 500 * time.Millisecond}

	switch t.Protocol {
	case "tcp":
		return d.Dial("tcp4", t.IP.String()+":"+strconv.Itoa(t.Port))
	default:
	}
	return nil, errors.Errorf("Unknown protocol: %s", t.Protocol)
}
