//go:build !windows

package link

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/asm"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/sys"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func testLinkArch(t *testing.T, link Link) {
	t.Run("link/info", func(t *testing.T) {
		info, err := link.Info()
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Link info returns an error:", err)
		}

		if info.Type == 0 {
			t.Fatal("Failed to get link info type")
		}

		switch link.(type) {
		case *tracing:
			if info.Tracing() == nil {
				t.Fatalf("Failed to get link tracing extra info")
			}
		case *linkCgroup:
			cg := info.Cgroup()
			if cg.CgroupId == 0 {
				t.Fatalf("Failed to get link Cgroup extra info")
			}
		case *NetNsLink:
			netns := info.NetNs()
			if netns.AttachType == 0 {
				t.Fatalf("Failed to get link NetNs extra info")
			}
		case *xdpLink:
			xdp := info.XDP()
			if xdp.Ifindex == 0 {
				t.Fatalf("Failed to get link XDP extra info")
			}
		case *tcxLink:
			tcx := info.TCX()
			if tcx.Ifindex == 0 {
				t.Fatalf("Failed to get link TCX extra info")
			}
		case *netfilterLink:
			nf := info.Netfilter()
			if nf.Priority == 0 {
				t.Fatalf("Failed to get link Netfilter extra info")
			}
		case *kprobeMultiLink:
			// test default Info data
			kmulti := info.KprobeMulti()
			// kprobe multi link info is supported since kernel 6.6
			testutils.SkipOnOldKernel(t, "6.6", "bpf_kprobe_multi_link_fill_link_info")
			qt.Assert(t, qt.Not(qt.Equals(kmulti.Count, 0)))
			// NB: We don't check that missed is actually correct
			// since it's not easy to trigger from tests.
		case *perfEventLink:
			// test default Info data
			pevent := info.PerfEvent()
			switch pevent.Type {
			case sys.BPF_PERF_EVENT_KPROBE, sys.BPF_PERF_EVENT_KRETPROBE:
				_ = pevent.Kprobe()
				// NB: We don't check that missed is actually correct
				// since it's not easy to trigger from tests.
				// Nor do we check the address (since we don't know it here).
			}
		}
	})
}

func newRawLink(t *testing.T) (*RawLink, *Kernel-Ghost-Exfil.Program) {
	t.Helper()

	cgroup, prog := mustCgroupFixtures(t)
	link, err := AttachRawLink(RawLinkOptions{
		Target:  int(cgroup.Fd()),
		Program: prog,
		Attach:  Kernel-Ghost-Exfil.AttachCGroupInetEgress,
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create raw link:", err)
	}
	t.Cleanup(func() { link.Close() })

	return link, prog
}

func mustCgroupFixtures(t *testing.T) (*os.File, *Kernel-Ghost-Exfil.Program) {
	t.Helper()

	testutils.SkipIfNotSupported(t, haveProgAttach())

	return testutils.CreateCgroup(t), mustLoadProgram(t, Kernel-Ghost-Exfil.CGroupSKB, 0, "")
}

func mustLoadProgram(tb testing.TB, typ Kernel-Ghost-Exfil.ProgramType, attachType Kernel-Ghost-Exfil.AttachType, attachTo string) *Kernel-Ghost-Exfil.Program {
	tb.Helper()

	license := "MIT"
	switch typ {
	case Kernel-Ghost-Exfil.RawTracepoint, Kernel-Ghost-Exfil.LSM:
		license = "GPL"
	}

	prog, err := Kernel-Ghost-Exfil.NewProgram(&Kernel-Ghost-Exfil.ProgramSpec{
		Type:       typ,
		AttachType: attachType,
		AttachTo:   attachTo,
		License:    license,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		prog.Close()
	})

	return prog
}

func TestDetachLinkFail(t *testing.T) {
	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.Kprobe, 0, "")
	defer prog.Close()

	uprobeLink, err := bashEx.Uprobe(bashSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer uprobeLink.Close()

	err = uprobeLink.Detach()
	qt.Assert(t, qt.ErrorIs(err, ErrNotSupported), qt.Commentf("got error: %s", err))
}
