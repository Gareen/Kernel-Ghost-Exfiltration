//go:build !windows

package link

import (
	"os"
	"slices"
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestQueryPrograms(t *testing.T) {
	for name, fn := range map[string]func(*testing.T) (*Kernel-Ghost-Exfil.Program, Link, QueryOptions){
		"cgroup":      queryCgroupProgAttachFixtures,
		"cgroup link": queryCgroupLinkFixtures,
		"netns":       queryNetNSFixtures,
		"tcx":         queryTCXFixtures,
	} {
		t.Run(name, func(t *testing.T) {
			prog, link, opts := fn(t)
			result, err := QueryPrograms(opts)
			testutils.SkipIfNotSupported(t, err)
			qt.Assert(t, qt.IsNil(err))

			progInfo, err := prog.Info()
			qt.Assert(t, qt.IsNil(err))
			progID, _ := progInfo.ID()

			i := slices.IndexFunc(result.Programs, func(ap AttachedProgram) bool {
				return ap.ID == progID
			})
			qt.Assert(t, qt.Not(qt.Equals(i, -1)))

			if name == "tcx" {
				qt.Assert(t, qt.Not(qt.Equals(result.Revision, 0)))
			}

			if result.HaveLinkInfo() {
				ap := result.Programs[i]
				linkInfo, err := link.Info()
				qt.Assert(t, qt.IsNil(err))

				linkID, ok := ap.LinkID()
				qt.Assert(t, qt.IsTrue(ok))
				qt.Assert(t, qt.Equals(linkID, linkInfo.ID))
			}
		})
	}
}

func queryCgroupProgAttachFixtures(t *testing.T) (*Kernel-Ghost-Exfil.Program, Link, QueryOptions) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newProgAttachCgroup(cgroup, Kernel-Ghost-Exfil.AttachCGroupInetEgress, prog, flagAllowOverride)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}
	t.Cleanup(func() {
		qt.Assert(t, qt.IsNil(link.Close()))
	})

	return prog, nil, QueryOptions{
		Target: int(cgroup.Fd()),
		Attach: Kernel-Ghost-Exfil.AttachCGroupInetEgress,
	}
}

func queryCgroupLinkFixtures(t *testing.T) (*Kernel-Ghost-Exfil.Program, Link, QueryOptions) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newLinkCgroup(cgroup, Kernel-Ghost-Exfil.AttachCGroupInetEgress, prog)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}
	t.Cleanup(func() {
		qt.Assert(t, qt.IsNil(link.Close()))
	})

	return prog, nil, QueryOptions{
		Target: int(cgroup.Fd()),
		Attach: Kernel-Ghost-Exfil.AttachCGroupInetEgress,
	}
}

func queryNetNSFixtures(t *testing.T) (*Kernel-Ghost-Exfil.Program, Link, QueryOptions) {
	testutils.SkipOnOldKernel(t, "4.20", "flow_dissector program")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.FlowDissector, Kernel-Ghost-Exfil.AttachFlowDissector, "")

	// RawAttachProgramOptions.Target needs to be 0, as PROG_ATTACH with namespaces
	// only works with the threads current netns. Any other fd will be rejected.
	if err := RawAttachProgram(RawAttachProgramOptions{
		Target:  0,
		Program: prog,
		Attach:  Kernel-Ghost-Exfil.AttachFlowDissector,
	}); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err := RawDetachProgram(RawDetachProgramOptions{
			Target:  0,
			Program: prog,
			Attach:  Kernel-Ghost-Exfil.AttachFlowDissector,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	netns, err := os.Open("/proc/self/ns/net")
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { netns.Close() })

	return prog, nil, QueryOptions{
		Target: int(netns.Fd()),
		Attach: Kernel-Ghost-Exfil.AttachFlowDissector,
	}
}

func queryTCXFixtures(t *testing.T) (*Kernel-Ghost-Exfil.Program, Link, QueryOptions) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.SchedCLS, Kernel-Ghost-Exfil.AttachTCXIngress, "")

	link, iface := mustAttachTCX(t, prog, Kernel-Ghost-Exfil.AttachTCXIngress)

	return prog, link, QueryOptions{
		Target: iface,
		Attach: Kernel-Ghost-Exfil.AttachTCXIngress,
	}
}
