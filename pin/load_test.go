package pin

import (
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/asm"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/platform"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils/testmain"
)

func mustPinnedProgram(t *testing.T, path string) *Kernel-Ghost-Exfil.Program {
	t.Helper()

	typ := Kernel-Ghost-Exfil.SocketFilter
	if platform.IsWindows {
		typ = Kernel-Ghost-Exfil.WindowsSample
	}

	spec := &Kernel-Ghost-Exfil.ProgramSpec{
		Name: "test",
		Type: typ,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 2, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	p, err := Kernel-Ghost-Exfil.NewProgram(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	if err := p.Pin(path); err != nil {
		t.Fatal(err)
	}

	return p
}

func mustPinnedMap(t *testing.T, path string) *Kernel-Ghost-Exfil.Map {
	t.Helper()

	typ := Kernel-Ghost-Exfil.Array
	if platform.IsWindows {
		typ = Kernel-Ghost-Exfil.WindowsArray
	}

	spec := &Kernel-Ghost-Exfil.MapSpec{
		Name:       "test",
		Type:       typ,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}

	m, err := Kernel-Ghost-Exfil.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })

	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}

	return m
}

func TestLoad(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.10", "reading program fdinfo")

	tmp := testutils.TempBPFFS(t)

	mpath := filepath.Join(tmp, "map")
	ppath := filepath.Join(tmp, "prog")

	mustPinnedMap(t, mpath)
	mustPinnedProgram(t, ppath)

	_, err := Load(tmp, nil)
	qt.Assert(t, qt.IsNotNil(err))

	m, err := Load(mpath, nil)
	qt.Assert(t, qt.IsNil(err))
	defer m.Close()
	qt.Assert(t, qt.Satisfies(m, testutils.Contains[*Kernel-Ghost-Exfil.Map]))

	p, err := Load(ppath, nil)
	qt.Assert(t, qt.IsNil(err))
	defer p.Close()
	qt.Assert(t, qt.Satisfies(p, testutils.Contains[*Kernel-Ghost-Exfil.Program]))
}

func TestMain(m *testing.M) {
	testmain.Run(m)
}
