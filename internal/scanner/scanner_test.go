package scanner

import (
	"net"
	"testing"
)

func TestScanTCP(t *testing.T) {
	type args struct {
		tuples []Tuple
	}

	p := 20000
	tuples := make([]Tuple, 0)
	for ; p < 20100; p += 1 {
		tuples = append(tuples, NewTuple("tcp", net.ParseIP("127.0.0.1"), p))
	}

	tests := []struct {
		name string
		args args
	}{
		{name: "(tcp) 127.0.0.1:20000-20099", args: struct{ tuples []Tuple }{tuples: tuples}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ScanTCP(tt.args.tuples)
		})
	}
}

func TestScanUDP(t *testing.T) {
	type args struct {
		tuples []Tuple
	}

	p := 10000
	tuples := make([]Tuple, 0)
	for ; p < 10010; p += 1 {
		tuples = append(tuples, NewTuple("udp", net.ParseIP("127.0.0.1"), p))
	}

	tests := []struct {
		name string
		args args
		want []Tuple
	}{
		{name: "(udp) 127.0.0.1:10000-10009", args: struct{ tuples []Tuple }{tuples: tuples}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ScanUDP(tt.args.tuples)
		})
	}
}

func TestScanICMP(t *testing.T) {
	type args struct {
		tuples []Tuple
	}

	tuple := Tuple{
		Protocol: "icmp",
		IP:       []byte{127, 0, 0, 1},
		Port:     0,
	}

	tests := []struct {
		name string
		args args
		want []Tuple
	}{
		{name: "127.0.0.1", args: struct{ tuples []Tuple }{tuples: []Tuple{tuple}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ScanICMP(tt.args.tuples)
		})
	}
}
