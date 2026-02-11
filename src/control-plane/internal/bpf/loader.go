// Package bpf handles loading and attaching the XDP BPF program.
package bpf

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// Objects holds all BPF map and program references.
type Objects struct {
	// Programs
	XDPProgram *ebpf.Program `ebpf:"xdp_ddos_scrubber"`

	// Maps
	ConfigMap     *ebpf.Map `ebpf:"config_map"`
	BlacklistV4   *ebpf.Map `ebpf:"blacklist_v4"`
	WhitelistV4   *ebpf.Map `ebpf:"whitelist_v4"`
	RateLimitMap  *ebpf.Map `ebpf:"rate_limit_map"`
	ConntrackMap  *ebpf.Map `ebpf:"conntrack_map"`
	SYNCookieMap  *ebpf.Map `ebpf:"syn_cookie_map"`
	AttackSigMap  *ebpf.Map `ebpf:"attack_sig_map"`
	AttackSigCnt  *ebpf.Map `ebpf:"attack_sig_count"`
	StatsMap      *ebpf.Map `ebpf:"stats_map"`
	Events        *ebpf.Map `ebpf:"events"`
	GlobalRateMap *ebpf.Map `ebpf:"global_rate_map"`
	GREtunnels    *ebpf.Map `ebpf:"gre_tunnels"`
	PortProtoMap  *ebpf.Map `ebpf:"port_proto_map"`
}

// Loader manages the lifecycle of BPF programs and maps.
type Loader struct {
	log     *zap.Logger
	objPath string
	objs    *Objects
	xdpLink link.Link
	iface   string
}

// NewLoader creates a new BPF loader.
func NewLoader(log *zap.Logger, objPath string) *Loader {
	return &Loader{
		log:     log,
		objPath: objPath,
	}
}

// Load reads the compiled BPF object file and loads programs/maps into the kernel.
func (l *Loader) Load() error {
	l.log.Info("loading BPF object", zap.String("path", l.objPath))

	// Verify the object file exists
	if _, err := os.Stat(l.objPath); os.IsNotExist(err) {
		return fmt.Errorf("BPF object not found: %s", l.objPath)
	}

	spec, err := ebpf.LoadCollectionSpec(l.objPath)
	if err != nil {
		return fmt.Errorf("loading collection spec: %w", err)
	}

	objs := &Objects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "", // No pinning by default
		},
	}); err != nil {
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	l.objs = objs
	l.log.Info("BPF objects loaded successfully",
		zap.String("program", "xdp_ddos_scrubber"),
		zap.Int("maps", 13),
	)

	return nil
}

// Attach attaches the XDP program to the given network interface.
func (l *Loader) Attach(ifaceName string, flags link.XDPAttachFlags) error {
	if l.objs == nil || l.objs.XDPProgram == nil {
		return fmt.Errorf("BPF program not loaded")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   l.objs.XDPProgram,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP to %s: %w", ifaceName, err)
	}

	l.xdpLink = xdpLink
	l.iface = ifaceName

	l.log.Info("XDP program attached",
		zap.String("interface", ifaceName),
		zap.Int("ifindex", iface.Index),
	)

	return nil
}

// Detach removes the XDP program from the interface.
func (l *Loader) Detach() error {
	if l.xdpLink != nil {
		l.log.Info("detaching XDP program", zap.String("interface", l.iface))
		if err := l.xdpLink.Close(); err != nil {
			return fmt.Errorf("detaching XDP: %w", err)
		}
		l.xdpLink = nil
	}
	return nil
}

// Close releases all BPF resources.
func (l *Loader) Close() error {
	var firstErr error

	if err := l.Detach(); err != nil && firstErr == nil {
		firstErr = err
	}

	if l.objs != nil {
		maps := []*ebpf.Map{
			l.objs.ConfigMap, l.objs.BlacklistV4, l.objs.WhitelistV4,
			l.objs.RateLimitMap, l.objs.ConntrackMap, l.objs.SYNCookieMap,
			l.objs.AttackSigMap, l.objs.AttackSigCnt, l.objs.StatsMap,
			l.objs.Events, l.objs.GlobalRateMap, l.objs.GREtunnels,
			l.objs.PortProtoMap,
		}
		for _, m := range maps {
			if m != nil {
				m.Close()
			}
		}
		if l.objs.XDPProgram != nil {
			l.objs.XDPProgram.Close()
		}
	}

	l.log.Info("BPF resources released")
	return firstErr
}

// Objects returns the loaded BPF objects for map operations.
func (l *Loader) Objects() *Objects {
	return l.objs
}

// ProgramInfo returns information about the loaded XDP program.
func (l *Loader) ProgramInfo() (*ebpf.ProgramInfo, error) {
	if l.objs == nil || l.objs.XDPProgram == nil {
		return nil, fmt.Errorf("program not loaded")
	}
	return l.objs.XDPProgram.Info()
}
