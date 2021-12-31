package scanner

import (
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ParseIP 解析用户输入的IP字段，返回多个IP地址
func ParseIP(s string) ([]net.IP, error) {
	var ips []net.IP

	// 消除空格
	s = strings.ReplaceAll(s, " ", "")
	// 解析多个网络段，用","隔开
	segments := strings.Split(s, ",")

	for _, segment := range segments {
		ss := strings.Split(segment, "/")
		if len(ss) == 2 {
			// case 1: 192.168.1.1/24
			ipAddr, ipNet, err := net.ParseCIDR(segment)
			if err != nil {
				return nil, errors.Errorf("Parsing IP network went wrong: %s", segment)
			}
			// 遍历这个网络段中的所有IP地址
			for ip := ipAddr.Mask(ipNet.Mask); ipNet.Contains(ip); increment(ip) {
				ip2 := make(net.IP, len(ip))
				copy(ip2, ip)
				ips = append(ips, ip2)
			}
		} else if len(ss) == 1 {
			// case 2: 192.168.1.1
			ip := net.ParseIP(ss[0])
			if ip == nil {
				return nil, errors.Errorf("Parsing singleton IP went wrong: %s", ss[0])
			}
			ips = append(ips, ip)
		} else {
			return nil, errors.Errorf("Wrong format: %s", segment)
		}
	}

	if len(ips) == 0 {
		return nil, errors.New("no IP")
	}

	return ips, nil
}

// ParsePort 解析用户输入的port字段，返回多个端口数
func ParsePort(s string) ([]int, error) {
	var ports []int

	// 消除空格
	s = strings.ReplaceAll(s, " ", "")
	// 解析多个端口，用","隔开
	segments := strings.Split(s, ",")

	for _, segment := range segments {
		ss := strings.Split(segment, "-")
		if len(ss) == 2 {
			// case 1: 10000-20000
			start, err := strconv.ParseUint(ss[0], 10, 16)
			if err != nil {
				return nil, errors.Errorf("Parsing %s went wrong: %s", segment, err.Error())
			}
			end, err := strconv.ParseUint(ss[1], 10, 16)
			if err != nil {
				return nil, errors.Errorf("Parsing %s went wrong: %s", segment, err.Error())
			}
			if end < start {
				return nil, errors.Errorf("Parsing %s went wrong: expected %d < %d", segment, start, end)
			}
			// 遍历范围内的所有端口号
			for i := start; i <= end; i++ {
				ports = append(ports, int(i))
			}
		} else if len(ss) == 1 {
			// case 2: 10000
			port, err := strconv.ParseUint(ss[0], 10, 16)
			if err != nil {
				return nil, errors.Errorf("Parsing singleton port %s went wrong: %s", ss[0], err.Error())
			}
			ports = append(ports, int(port))
		} else {
			return nil, errors.Errorf("Wrong format: %s", segment)
		}

	}

	if len(ports) == 0 {
		return nil, errors.New("no Port")
	}

	return ports, nil
}

// increment 将IP地址+1
func increment(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
