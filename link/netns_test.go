//go:build !windows

package link

import (
	"os"
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/asm"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func TestSkLookup(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "sk_lookup program")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.SkLookup, Kernel-Ghost-Exfil.AttachSkLookup, "")

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer netns.Close()

	link, err := AttachNetNs(int(netns.Fd()), prog)
	if err != nil {
		t.Fatal("Can't attach link:", err)
	}

	testLink(t, link, prog)
}

func createSkLookupProgram() (*Kernel-Ghost-Exfil.Program, error) {
	prog, err := Kernel-Ghost-Exfil.NewProgram(&Kernel-Ghost-Exfil.ProgramSpec{
		Type:       Kernel-Ghost-Exfil.SkLookup,
		AttachType: Kernel-Ghost-Exfil.AttachSkLookup,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return nil, err
	}
	return prog, nil
}

func ExampleAttachNetNs() {
	prog, err := createSkLookupProgram()
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	// This can be a path to another netns as well.
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		panic(err)
	}
	defer netns.Close()

	link, err := AttachNetNs(int(netns.Fd()), prog)
	if err != nil {
		panic(err)
	}

	// The socket lookup program is now active until Close().
	link.Close()
}
