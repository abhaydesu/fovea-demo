// Package identity maps kernel-level identifiers (tgid, IP, cgroup) to
// service names. The Resolver interface is the seam where a Kubernetes
// (pod name / namespace) implementation plugs in later.
package identity

// Resolver turns process and network identities into service names.
type Resolver interface {
	// ServiceByPID returns the service owning a process ("" if unknown).
	ServiceByPID(tgid uint32) string
	// ServiceByIP returns the service owning an IP address ("" if unknown).
	ServiceByIP(ip string) string
	// CgroupIDs returns cgroup ids of all workloads Fovea should capture.
	CgroupIDs() map[uint64]bool
	// Interfaces returns host-side network interface indexes of the workloads (for flow capture).
	Interfaces() []int
	// Refresh re-reads the workload inventory.
	Refresh() error
}
