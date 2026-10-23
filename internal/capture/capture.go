// Package capture loads the Fovea eBPF programs and streams raw payload
// events out of the kernel ring buffer.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I../../bpf" fovea ../../bpf/fovea.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I../../bpf" flows ../../bpf/flows.bpf.c

const (
	DirSend = 0
	DirRecv = 1

	maxData   = 4096
	dataStart = 84 // offset of data[] in struct event (see bpf/fovea.bpf.c)
)

// Event is one captured chunk of bytes a process sent or received on a TCP socket.
type Event struct {
	TimeNs     uint64 // CLOCK_MONOTONIC
	TGID, PID  uint32
	FD         uint32
	SyscallLen uint32
	Dir        uint8
	Comm       string
	LAddr      net.IP
	RAddr      net.IP
	LPort      uint16
	RPort      uint16
	Data       []byte
}

func parseEvent(raw []byte) (*Event, error) {
	if len(raw) < dataStart {
		return nil, fmt.Errorf("short event: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	e := &Event{
		TimeNs:     le.Uint64(raw[0:]),
		TGID:       le.Uint32(raw[8:]),
		PID:        le.Uint32(raw[12:]),
		FD:         le.Uint32(raw[16:]),
		SyscallLen: le.Uint32(raw[20:]),
		Dir:        raw[28],
		LPort:      le.Uint16(raw[30:]),
		RPort:      le.Uint16(raw[32:]),
	}
	dlen := int(le.Uint32(raw[24:]))
	family := raw[29]
	if family == 2 {
		e.LAddr = net.IP(append([]byte(nil), raw[36:40]...))
		e.RAddr = net.IP(append([]byte(nil), raw[52:56]...))
	} else {
		l := net.IP(append([]byte(nil), raw[36:52]...))
		r := net.IP(append([]byte(nil), raw[52:68]...))
		if v4 := l.To4(); v4 != nil { // v4-mapped IPv6 (Go listens on [::]:port)
			l = v4
		}
		if v4 := r.To4(); v4 != nil {
			r = v4
		}
		e.LAddr, e.RAddr = l, r
	}
	e.Comm = string(bytes.TrimRight(raw[68:84], "\x00"))
	if dlen > maxData || dataStart+dlen > len(raw) {
		dlen = len(raw) - dataStart
		if dlen > maxData {
			dlen = maxData
		}
	}
	e.Data = append([]byte(nil), raw[dataStart:dataStart+dlen]...)
	return e, nil
}

// Capture owns the loaded programs, tracepoint links and ring buffer.
type Capture struct {
	objs  foveaObjects
	links []link.Link
	rd    *ringbuf.Reader
}

// New loads and attaches all programs.
func New() (*Capture, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &Capture{}
	if err := loadFoveaObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	var err error
	add := func(group, name string, prog *ebpf.Program) {
		if err != nil {
			return
		}
		l, e := link.Tracepoint(group, name, prog, nil)
		if e != nil {
			err = fmt.Errorf("attach %s/%s: %w", group, name, e)
			return
		}
		c.links = append(c.links, l)
	}
	add("syscalls", "sys_enter_write", c.objs.TpEnterWrite)
	add("syscalls", "sys_exit_write", c.objs.TpExitWrite)
	add("syscalls", "sys_enter_sendto", c.objs.TpEnterSendto)
	add("syscalls", "sys_exit_sendto", c.objs.TpExitSendto)
	add("syscalls", "sys_enter_read", c.objs.TpEnterRead)
	add("syscalls", "sys_exit_read", c.objs.TpExitRead)
	add("syscalls", "sys_enter_recvfrom", c.objs.TpEnterRecvfrom)
	add("syscalls", "sys_exit_recvfrom", c.objs.TpExitRecvfrom)
	add("syscalls", "sys_enter_writev", c.objs.TpEnterWritev)
	add("syscalls", "sys_exit_writev", c.objs.TpExitWritev)
	add("syscalls", "sys_enter_readv", c.objs.TpEnterReadv)
	add("syscalls", "sys_exit_readv", c.objs.TpExitReadv)
	add("syscalls", "sys_enter_sendmsg", c.objs.TpEnterSendmsg)
	add("syscalls", "sys_exit_sendmsg", c.objs.TpExitSendmsg)
	add("syscalls", "sys_enter_recvmsg", c.objs.TpEnterRecvmsg)
	add("syscalls", "sys_exit_recvmsg", c.objs.TpExitRecvmsg)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.rd, err = ringbuf.NewReader(c.objs.Events)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	return c, nil
}

// SetAllowedCgroups restricts capture (in-kernel) to the given cgroup ids.
// An empty set disables filtering.
func (c *Capture) SetAllowedCgroups(ids map[uint64]bool) error {
	var iter = c.objs.AllowedCgroups.Iterate()
	var k uint64
	var v uint8
	var stale []uint64
	for iter.Next(&k, &v) {
		if !ids[k] {
			stale = append(stale, k)
		}
	}
	for _, k := range stale {
		_ = c.objs.AllowedCgroups.Delete(k)
	}
	for id := range ids {
		if err := c.objs.AllowedCgroups.Put(id, uint8(1)); err != nil {
			return err
		}
	}
	on := uint32(0)
	if len(ids) > 0 {
		on = 1
	}
	return c.objs.FilterOn.Put(uint32(0), on)
}

// Run reads events until ctx is cancelled and sends them to out.
func (c *Capture) Run(ctx context.Context, out chan<- *Event) error {
	go func() { <-ctx.Done(); c.rd.Close() }()
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		ev, err := parseEvent(rec.RawSample)
		if err != nil {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// Close detaches the programs and frees kernel resources.
func (c *Capture) Close() {
	if c.rd != nil {
		c.rd.Close()
	}
	for _, l := range c.links {
		l.Close()
	}
	c.objs.Close()
}

// Stats returns (events seen, events dropped because the ring buffer was full).
func (c *Capture) Stats() (seen, dropped uint64) {
	sum := func(idx uint32) uint64 {
		var vals []uint64
		if err := c.objs.Stats.Lookup(idx, &vals); err != nil {
			return 0
		}
		var t uint64
		for _, v := range vals {
			t += v
		}
		return t
	}
	return sum(1), sum(0)
}
