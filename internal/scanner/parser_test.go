package scanner

import (
	"net"
	"reflect"
	"testing"
)

func TestParseIP(t *testing.T) {
	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    []net.IP
		wantErr bool
	}{
		{
			name:    "127.0.0.1",
			args:    struct{ s string }{s: "127.0.0.1"},
			want:    []net.IP{net.ParseIP("127.0.0.1")},
			wantErr: false,
		},
		{
			name: "10.10.10.5/30",
			args: struct{ s string }{s: "10.10.10.5/30"},
			want: []net.IP{
				net.ParseIP("10.10.10.4"),
				net.ParseIP("10.10.10.5"),
				net.ParseIP("10.10.10.6"),
				net.ParseIP("10.10.10.7"),
			},
			wantErr: false,
		},
		{
			name: "123.123.123.123 , 172.169.100.1/31",
			args: struct{ s string }{s: "123.123.123.123 , 172.169.100.1/31"},
			want: []net.IP{
				net.ParseIP("123.123.123.123"),
				net.ParseIP("172.169.100.0"),
				net.ParseIP("172.169.100.1"),
			},
			wantErr: false,
		},
		{
			name:    "123.123.123..123",
			args:    struct{ s string }{s: "123.123.123..123"},
			want:    []net.IP{},
			wantErr: true,
		},
		{
			name:    "1234.123.123.123",
			args:    struct{ s string }{s: "1234.123.123.123"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "abcedgh",
			args:    struct{ s string }{s: "abcedgh"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIP(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && tt.want == nil {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParseIP() got = %v, want %v", got, tt.want)
				return
			}
			if len(got) > 0 {
				for i := 0; i < len(got); i++ {
					if !got[i].Equal(tt.want[i]) {
						t.Errorf("ParseIP() got = %v, want %v", got, tt.want)
						return
					}
				}
			}

		})
	}
}

func TestParsePort(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []int
		wantErr bool
	}{
		{
			name:    "10000",
			args:    struct{ s string }{s: "10000"},
			want:    []int{10000},
			wantErr: false,
		},
		{
			name:    "10000-10005",
			args:    struct{ s string }{s: "10000-10005"},
			want:    []int{10000, 10001, 10002, 10003, 10004, 10005},
			wantErr: false,
		},
		{
			name:    "80, 443, 8000-8005",
			args:    struct{ s string }{s: "80, 443, 8000-8005"},
			want:    []int{80, 443, 8000, 8001, 8002, 8003, 8004, 8005},
			wantErr: false,
		},
		{
			name:    "9999-8888,6666-7777",
			args:    struct{ s string }{s: "9999-8888,6666-7777"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "100000",
			args:    struct{ s string }{s: "100000"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "abcefgh,",
			args:    struct{ s string }{s: "abcefgh,"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePort(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePort() got = %v, want %v", got, tt.want)
			}
		})
	}
}
