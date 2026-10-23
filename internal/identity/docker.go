package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Docker resolves identities through the docker CLI and /proc/<pid>/cgroup.
// Only containers belonging to the given compose project are considered.
type Docker struct {
	project string

	mu       sync.RWMutex
	byID     map[string]string // container id -> service
	byIP     map[string]string
	cgroups  map[uint64]bool
	ifaces   []int
	pidCache map[uint32]string
}

func NewDocker(composeProject string) *Docker {
	return &Docker{project: composeProject, byID: map[string]string{}, byIP: map[string]string{},
		cgroups: map[uint64]bool{}, pidCache: map[uint32]string{}}
}

type inspect struct {
	ID     string
	Config struct{ Labels map[string]string }
	State  struct {
		Running bool
		Pid     int
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func (d *Docker) Refresh() error {
	ids, err := exec.Command("docker", "ps", "-q", "--no-trunc",
		"--filter", "label=com.docker.compose.project="+d.project).Output()
	if err != nil {
		return fmt.Errorf("docker ps: %w", err)
	}
	list := strings.Fields(string(ids))
	byID, byIP, cg := map[string]string{}, map[string]string{}, map[uint64]bool{}
	var ifaces []int
	if len(list) > 0 {
		out, err := exec.Command("docker", append([]string{"inspect"}, list...)...).Output()
		if err != nil {
			return fmt.Errorf("docker inspect: %w", err)
		}
		var cs []inspect
		if err := json.Unmarshal(out, &cs); err != nil {
			return err
		}
		for _, c := range cs {
			svc := c.Config.Labels["com.docker.compose.service"]
			if svc == "" {
				continue
			}
			byID[c.ID] = svc
			for _, n := range c.NetworkSettings.Networks {
				if n.IPAddress != "" {
					byIP[n.IPAddress] = svc
				}
			}
			if idx, ok := hostIfindex(c.State.Pid); ok {
				ifaces = append(ifaces, idx)
			}
			if id, ok := cgroupID(c.ID); ok {
				cg[id] = true
			}
		}
	}
	d.mu.Lock()
	d.byID, d.byIP, d.cgroups, d.ifaces = byID, byIP, cg, ifaces
	d.pidCache = map[uint32]string{}
	d.mu.Unlock()
	return nil
}

// hostIfindex finds the host-side veth peer of a container's eth0: the container's
// eth0/iflink holds the host interface index.
func hostIfindex(pid int) (int, bool) {
	if pid <= 0 {
		return 0, false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/sys/class/net/eth0/iflink", pid))
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return n, err == nil && n > 0
}

func (d *Docker) Interfaces() []int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]int(nil), d.ifaces...)
}

// cgroupID returns the cgroup v2 id (inode of the cgroup directory).
func cgroupID(containerID string) (uint64, bool) {
	for _, p := range []string{
		"/sys/fs/cgroup/system.slice/docker-" + containerID + ".scope",
		"/sys/fs/cgroup/docker/" + containerID,
	} {
		var st syscall.Stat_t
		if syscall.Stat(p, &st) == nil {
			return st.Ino, true
		}
	}
	return 0, false
}

var cidRe = regexp.MustCompile(`([0-9a-f]{64})`)

func (d *Docker) ServiceByPID(tgid uint32) string {
	d.mu.RLock()
	s, ok := d.pidCache[tgid]
	d.mu.RUnlock()
	if ok {
		return s
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", tgid))
	if err != nil {
		return ""
	}
	id := cidRe.FindString(string(b))
	d.mu.Lock()
	defer d.mu.Unlock()
	svc := d.byID[id]
	if svc != "" {
		d.pidCache[tgid] = svc
	}
	return svc
}

func (d *Docker) ServiceByIP(ip string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byIP[ip]
}

func (d *Docker) CgroupIDs() map[uint64]bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[uint64]bool, len(d.cgroups))
	for k := range d.cgroups {
		out[k] = true
	}
	return out
}
