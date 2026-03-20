//go:build !windows

package link

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func TestAttachNetfilter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.4", "BPF_LINK_TYPE_NETFILTER")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.Netfilter, Kernel-Ghost-Exfil.AttachNetfilter, "")

	l, err := AttachNetfilter(NetfilterOptions{
		Program:        prog,
		ProtocolFamily: NetfilterProtoIPv4,
		Hook:           NetfilterInetLocalOut,
		Priority:       -128,
	})
	if err != nil {
		t.Fatal(err)
	}

	info, err := l.Info()
	if err != nil {
		t.Fatal(err)
	}
	nfInfo := info.Netfilter()
	qt.Assert(t, qt.Equals(nfInfo.ProtocolFamily, NetfilterProtoIPv4))
	qt.Assert(t, qt.Equals(nfInfo.Hook, NetfilterInetLocalOut))
	qt.Assert(t, qt.Equals(nfInfo.Priority, -128))

	testLink(t, l, prog)
}
