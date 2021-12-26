package scanner

import (
	"net"
	"testing"
)

func TestScan(t *testing.T) {
	type args struct {
		tuples []Tuple
	}

	p := 20000
	tuples := make([]Tuple, 0)
	for ; p < 20100; p += 1 {
		tuples = append(tuples, NewTuple(net.ParseIP("127.0.0.1"), p, "tcp"))
	}

	tests := []struct {
		name string
		args args
	}{
		{name: "127.0.0.1:20000-20099", args: struct{ tuples []Tuple }{tuples: tuples}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Scan(tt.args.tuples)
		})
	}
}
