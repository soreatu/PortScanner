package scanner

import (
	"encoding/gob"
	"fmt"
	"net"
)

type State int

const (
	CLOSE State = iota
	OPEN
	FILTER
)

func init() {
	gob.Register(&Tuple{})
}

// Tuple describes a network port (protocol + ip + port) to be scanned.
type Tuple struct {
	Protocol   string `json:"protocol"`
	IP         net.IP `json:"ip"`
	Port       int    `json:"port,omitempty"`
	PortStatus State  `json:"state"`
}

// NewTuple creates a tuple with given data.
func NewTuple(protocol string, ip net.IP, port int) Tuple {
	return Tuple{
		IP:         ip,
		Port:       port,
		Protocol:   protocol,
		PortStatus: CLOSE, // default to "CLOSE"
	}
}

// IsOpen returns whether the network port is open or not.
func (t Tuple) IsOpen() bool {
	return t.PortStatus == OPEN
}

// SetOpen sets the port as "OPEN".
func (t *Tuple) SetOpen() {
	t.PortStatus = OPEN
}

// SetFilter sets the port as "FILTER".
func (t *Tuple) SetFilter() {
	t.PortStatus = FILTER
}

// String returns the string representation of a tuple.
func (t Tuple) String() string {
	return fmt.Sprintf("%s %s:%d", t.Protocol, t.IP.String(), t.Port)
}
