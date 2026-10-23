package capture

import (
	"encoding/binary"
	"testing"
)

// raw builds a record laid out exactly like struct event in bpf/fovea.bpf.c.
func raw(family uint8, laddr, raddr []byte, data string) []byte {
	b := make([]byte, dataStart+len(data))
	le := binary.LittleEndian
	le.PutUint64(b[0:], 42)
	le.PutUint32(b[8:], 100)  // tgid
	le.PutUint32(b[12:], 101) // pid
	le.PutUint32(b[16:], 7)   // fd
	le.PutUint32(b[20:], uint32(len(data)))
	le.PutUint32(b[24:], uint32(len(data)))
	b[28] = DirRecv
	b[29] = family
	le.PutUint16(b[30:], 8081)
	le.PutUint16(b[32:], 40000)
	copy(b[36:52], laddr)
	copy(b[52:68], raddr)
	copy(b[68:84], "orders")
	copy(b[dataStart:], data)
	return b
}

func TestParseEventIPv4(t *testing.T) {
	e, err := parseEvent(raw(2, []byte{10, 0, 0, 2}, []byte{10, 0, 0, 1}, "GET / HTTP/1.1\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e.TGID != 100 || e.FD != 7 || e.Dir != DirRecv || e.LPort != 8081 || e.RPort != 40000 ||
		e.LAddr.String() != "10.0.0.2" || e.RAddr.String() != "10.0.0.1" || e.Comm != "orders" || string(e.Data) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("%+v", e)
	}
}

func TestParseEventV4MappedIPv6(t *testing.T) {
	m := func(a, b, c, d byte) []byte { return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d} }
	e, err := parseEvent(raw(10, m(172, 18, 0, 3), m(172, 18, 0, 4), "x"))
	if err != nil {
		t.Fatal(err)
	}
	if e.LAddr.String() != "172.18.0.3" || e.RAddr.String() != "172.18.0.4" {
		t.Fatalf("v4-mapped not unmapped: %s %s", e.LAddr, e.RAddr)
	}
}

func TestParseEventShortAndLyingLength(t *testing.T) {
	if _, err := parseEvent(make([]byte, 10)); err == nil {
		t.Fatal("short record must error")
	}
	b := raw(2, []byte{1, 2, 3, 4}, []byte{1, 2, 3, 4}, "abc")
	binary.LittleEndian.PutUint32(b[24:], 9999) // data_len larger than the record
	e, err := parseEvent(b)
	if err != nil || string(e.Data) != "abc" {
		t.Fatalf("must clamp to record size: %v %q", err, e.Data)
	}
}
