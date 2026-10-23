package netflow

import (
	"testing"
	"time"

	"fovea/internal/capture"
)

type res struct{}

func (res) ServiceByPID(uint32) string { return "" }
func (res) ServiceByIP(ip string) string {
	return map[string]string{"10.0.0.1": "orders", "10.0.0.2": "inventory"}[ip]
}
func (res) CgroupIDs() map[uint64]bool { return nil }
func (res) Interfaces() []int          { return nil }
func (res) Refresh() error             { return nil }

func TestMergeBothDirections(t *testing.T) {
	now := time.Now()
	raw := []capture.Flow{
		{SrcIP: "10.0.0.1", SrcPort: 41000, DstIP: "10.0.0.2", DstPort: 8082, Proto: 6, Packets: 5, Bytes: 600, TCPFlags: 0x02 | 0x10, Last: now},
		{SrcIP: "10.0.0.2", SrcPort: 8082, DstIP: "10.0.0.1", DstPort: 41000, Proto: 6, Packets: 4, Bytes: 900, TCPFlags: 0x10 | 0x01, Last: now},
	}
	out := Merge(raw, res{})
	if len(out) != 1 {
		t.Fatalf("want 1 connection, got %d", len(out))
	}
	f := out[0]
	if f.Client != "10.0.0.1:41000" || f.Server != "10.0.0.2:8082" || f.PacketsOut != 5 || f.BytesIn != 900 ||
		f.ClientService != "orders" || f.ServerService != "inventory" || len(f.Flags) != 3 {
		t.Fatalf("%+v", f)
	}
}
