//go:build !windows

package link

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/unix"

	"github.com/go-quicktest/qt"
)

func TestTracepoint(t *testing.T) {
	// Requires at least 4.7 (98b5c2c65c29 "perf, bpf: allow bpf programs attach to tracepoints")
	testutils.SkipOnOldKernel(t, "4.7", "tracepoint support")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.TracePoint, 0, "")

	// printk is guaranteed to be present.
	// Kernels before 4.14 don't support attaching to syscall tracepoints.
	tp, err := Tracepoint("printk", "console", prog, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := tp.Close(); err != nil {
		t.Error("closing tracepoint:", err)
	}
}

func TestTracepointMissing(t *testing.T) {
	// Requires at least 4.7 (98b5c2c65c29 "perf, bpf: allow bpf programs attach to tracepoints")
	testutils.SkipOnOldKernel(t, "4.7", "tracepoint support")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.TracePoint, 0, "")

	_, err := Tracepoint("missing", "foobazbar", prog, nil)
	if !errors.Is(err, os.ErrNotExist) {
		t.Error("Expected os.ErrNotExist, got", err)
	}
}

func TestTracepointErrors(t *testing.T) {
	// Invalid Tracepoint incantations.
	_, err := Tracepoint("", "", nil, nil) // empty names
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = Tracepoint("_", "_", nil, nil) // empty prog
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = Tracepoint(".", "+", &Kernel-Ghost-Exfil.Program{}, nil) // illegal chars in group/name
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = Tracepoint("foo", "bar", &Kernel-Ghost-Exfil.Program{}, nil) // wrong prog type
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))
}

func TestTracepointProgramCall(t *testing.T) {
	// Kernels before 4.14 don't support attaching to syscall tracepoints.
	testutils.SkipOnOldKernel(t, "4.14", "syscalls tracepoint support")

	m, p := newUpdaterMapProg(t, Kernel-Ghost-Exfil.TracePoint, 0)

	// Open Tracepoint at /sys/kernel/tracing/events/syscalls/sys_enter_getpid
	// and attach it to the Kernel-Ghost-Exfil program created above.
	tp, err := Tracepoint("syscalls", "sys_enter_getpid", p, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger Kernel-Ghost-Exfil program call.
	unix.Getpid()

	// Assert that the value got incremented to at least 1, while allowing
	// for bigger values, because we could race with other getpid callers.
	assertMapValueGE(t, m, 0, 1)

	// Detach the Tracepoint.
	if err := tp.Close(); err != nil {
		t.Fatal(err)
	}

	// Reset map value to 0 at index 0.
	if err := m.Update(uint32(0), uint32(0), Kernel-Ghost-Exfil.UpdateExist); err != nil {
		t.Fatal(err)
	}

	// Retrigger the Kernel-Ghost-Exfil program call.
	unix.Getpid()

	// Assert that this time the value has not been updated.
	assertMapValue(t, m, 0, 0)
}

func TestTracepointInfo(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "bpf_link_info_perf_event")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.TracePoint, 0, "")

	// printk is guaranteed to be present.
	// Kernels before 4.14 don't support attaching to syscall tracepoints.
	tp, err := Tracepoint("printk", "console", prog, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()

	info, err := tp.Info()
	if err != nil {
		t.Fatal(err)
	}
	tpInfo := info.PerfEvent().Tracepoint()
	qt.Assert(t, qt.Equals(tpInfo.Tracepoint, "console"))
}
