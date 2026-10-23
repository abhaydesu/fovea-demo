package capture

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Flow is the cumulative packet/byte count of one direction of one connection.
type Flow struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Proto            uint8
	Packets, Bytes   uint64
	TCPFlags         uint32
	First, Last      time.Time
}

// Flows attaches the flow counter program to container veth interfaces.
type Flows struct {
	objs    flowsObjects
	mu      sync.Mutex
	links   map[int]link.Link // ifindex -> link
	bootOff int64
}

func NewFlows() (*Flows, error) {
	f := &Flows{links: map[int]link.Link{}}
	if err := loadFlowsObjects(&f.objs, nil); err != nil {
		return nil, fmt.Errorf("load flow objects: %w", err)
	}
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	f.bootOff = time.Now().UnixNano() - ts.Nano()
	return f, nil
}

// SetInterfaces attaches to new ifindexes and detaches from vanished ones.
func (f *Flows) SetInterfaces(idx []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[int]bool{}
	for _, i := range idx {
		want[i] = true
		if f.links[i] != nil {
			continue
		}
		l, err := link.AttachTCX(link.TCXOptions{Interface: i, Program: f.objs.FlowIngress, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			continue
		}
		f.links[i] = l
	}
	for i, l := range f.links {
		if !want[i] {
			l.Close()
			delete(f.links, i)
		}
	}
}

func ipStr(v uint32) string {
	b := make([]byte, 4)
	// stored in network byte order as read from the packet
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	return net.IP(b).String()
}

// Snapshot dumps all flows currently in the kernel map.
func (f *Flows) Snapshot() []Flow {
	var out []Flow
	var k flowsFlowKey
	var v flowsFlowVal
	it := f.objs.Flows.Iterate()
	for it.Next(&k, &v) {
		out = append(out, Flow{
			SrcIP: ipStr(k.Saddr), DstIP: ipStr(k.Daddr), SrcPort: k.Sport, DstPort: k.Dport, Proto: k.Proto,
			Packets: v.Packets, Bytes: v.Bytes, TCPFlags: v.TcpFlags,
			First: time.Unix(0, int64(v.FirstNs)+f.bootOff), Last: time.Unix(0, int64(v.LastNs)+f.bootOff),
		})
	}
	return out
}

func (f *Flows) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.links {
		l.Close()
	}
	f.objs.Close()
}
