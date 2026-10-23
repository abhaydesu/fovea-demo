// Package netflow turns raw per-direction packet counters into per-connection flow
// records, labelled with service names. It plays the role Hubble plays in a Cilium
// cluster: network-level metadata that Fovea joins with payload transactions.
package netflow

import (
	"fmt"
	"sort"
	"time"

	"fovea/internal/capture"
	"fovea/internal/identity"
)

type Flow struct {
	ID            string    `json:"id"`
	Client        string    `json:"client"` // ip:port
	Server        string    `json:"server"`
	ClientService string    `json:"client_service"`
	ServerService string    `json:"server_service"`
	Proto         string    `json:"proto"`
	PacketsOut    uint64    `json:"packets_out"` // client -> server
	BytesOut      uint64    `json:"bytes_out"`
	PacketsIn     uint64    `json:"packets_in"` // server -> client
	BytesIn       uint64    `json:"bytes_in"`
	Flags         []string  `json:"tcp_flags,omitempty"`
	Last          time.Time `json:"last_seen"`
}

func proto(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	}
	return fmt.Sprint(p)
}

func flagNames(f uint32) []string {
	var out []string
	for _, x := range []struct {
		bit  uint32
		name string
	}{{0x02, "SYN"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x01, "FIN"}, {0x04, "RST"}} {
		if f&x.bit != 0 {
			out = append(out, x.name)
		}
	}
	return out
}

// isServerSide guesses the service end of a connection: the well-known (lower) port.
func isServerSide(port, other uint16) bool { return port < other }

// Merge pairs the two directions of each connection into one Flow record.
func Merge(raw []capture.Flow, res identity.Resolver) []Flow {
	byConn := map[string]*Flow{}
	for _, f := range raw {
		cIP, cPort, sIP, sPort := f.SrcIP, f.SrcPort, f.DstIP, f.DstPort
		out := true
		if isServerSide(f.SrcPort, f.DstPort) { // this packet stream goes server -> client
			cIP, cPort, sIP, sPort = f.DstIP, f.DstPort, f.SrcIP, f.SrcPort
			out = false
		}
		key := fmt.Sprintf("%s:%d>%s:%d/%d", cIP, cPort, sIP, sPort, f.Proto)
		c := byConn[key]
		if c == nil {
			c = &Flow{ID: key, Client: fmt.Sprintf("%s:%d", cIP, cPort), Server: fmt.Sprintf("%s:%d", sIP, sPort),
				ClientService: label(res.ServiceByIP(cIP)), ServerService: label(res.ServiceByIP(sIP)), Proto: proto(f.Proto)}
			byConn[key] = c
		}
		if out {
			c.PacketsOut += f.Packets
			c.BytesOut += f.Bytes
		} else {
			c.PacketsIn += f.Packets
			c.BytesIn += f.Bytes
		}
		seen := map[string]bool{}
		for _, n := range c.Flags {
			seen[n] = true
		}
		for _, n := range flagNames(f.TCPFlags) {
			if !seen[n] {
				c.Flags = append(c.Flags, n)
			}
		}
		if f.Last.After(c.Last) {
			c.Last = f.Last
		}
	}
	list := make([]Flow, 0, len(byConn))
	for _, c := range byConn {
		list = append(list, *c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Last.After(list[j].Last) })
	return list
}

func label(s string) string {
	if s == "" {
		return "external"
	}
	return s
}
