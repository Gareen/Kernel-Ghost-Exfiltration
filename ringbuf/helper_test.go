package ringbuf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/platform"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func mustRun(tb testing.TB, prog *Kernel-Ghost-Exfil.Program) {
	tb.Helper()

	opts := &Kernel-Ghost-Exfil.RunOptions{
		Data: internal.EmptyBPFContext,
	}
	if platform.IsWindows {
		opts.Context = make([]byte, 32)
	}

	ret, err := prog.Run(opts)
	testutils.SkipIfNotSupported(tb, err)
	qt.Assert(tb, qt.IsNil(err))

	qt.Assert(tb, qt.Equals(ret, uint32(0)))
}
