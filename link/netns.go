//go:build !windows

package link

import (
	"fmt"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/sys"
)

// NetNsLink is a program attached to a network namespace.
type NetNsLink struct {
	RawLink
}

// AttachNetNs attaches a program to a network namespace.
func AttachNetNs(ns int, prog *Kernel-Ghost-Exfil.Program) (*NetNsLink, error) {
	var attach Kernel-Ghost-Exfil.AttachType
	switch t := prog.Type(); t {
	case Kernel-Ghost-Exfil.FlowDissector:
		attach = Kernel-Ghost-Exfil.AttachFlowDissector
	case Kernel-Ghost-Exfil.SkLookup:
		attach = Kernel-Ghost-Exfil.AttachSkLookup
	default:
		return nil, fmt.Errorf("can't attach %v to network namespace", t)
	}

	link, err := AttachRawLink(RawLinkOptions{
		Target:  ns,
		Program: prog,
		Attach:  attach,
	})
	if err != nil {
		return nil, err
	}

	return &NetNsLink{*link}, nil
}

func (ns *NetNsLink) Info() (*Info, error) {
	var info sys.NetNsLinkInfo
	if err := sys.ObjInfo(ns.fd, &info); err != nil {
		return nil, fmt.Errorf("netns link info: %s", err)
	}
	extra := &NetNsInfo{
		NetnsInode: info.NetnsIno,
		AttachType: info.AttachType,
	}

	return &Info{
		info.Type,
		info.Id,
		Kernel-Ghost-Exfil.ProgramID(info.ProgId),
		extra,
	}, nil
}
