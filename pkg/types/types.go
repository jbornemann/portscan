package types

import (
	"fmt"
	"net"
	"strings"

	pnet "github.com/jbornemann/portscan/internal/net"
)

//ScanRequest represents a group of interesting IPs, and a port to scan
type ScanRequest struct {
	ScanIPs  []string `json:"ips"`
	ScanPort uint     `json:"port"`
}

//Validate will validate that the ScanRequest is valid, e.g that ips are indeed ip addresses
//Validate will return an error detailing what is wrong if validation fails
func (s ScanRequest) Validate() (bool, error) {
	messages := make([]string, 0)

	if s.ScanIPs == nil {
		messages = append(messages, "you must provide a list of ips")
	} else {
		for _, ip := range s.ScanIPs {
			if net.ParseIP(ip) == nil {
				messages = append(messages, fmt.Sprintf("%s is not a valid ip address", ip))
			}
		}
	}

	if !pnet.ValidPort(s.ScanPort) {
		messages = append(messages, fmt.Sprintf("%d is not a valid port number", s.ScanPort))
	}

	if len(messages) > 0 {
		return false, fmt.Errorf(strings.Join(messages, "\n"))
	}
	return true, nil
}

type ScanResponse struct {
	ScanID uint64 `json:"id"`
}

type QueryRequest struct {
	ScanID uint64 `json:"id"`
}

type QueryResponse struct {
	Ready    bool       `json:"ready"`
	ScanPort uint       `json:"port"`
	Status   []IPStatus `json:"status"`
}

type IPStatus struct {
	IP    string `json:"ip"`
	State State  `json:"state"`
}

type State string

const (
	OPEN   State = "open"
	CLOSED State = "closed"
)
