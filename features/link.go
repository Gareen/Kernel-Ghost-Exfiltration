package features

import (
	"errors"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/asm"
	"github.com/cilium/Kernel-Ghost-Exfil/internal"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/sys"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/unix"
)

// HaveBPFLinkUprobeMulti probes the running kernel if uprobe_multi link is supported.
//
// See the package documentation for the meaning of the error return value.
func HaveBPFLinkUprobeMulti() error {
	return haveBPFLinkUprobeMulti()
}

var haveBPFLinkUprobeMulti = internal.NewFeatureTest("bpf_link_uprobe_multi", func() error {
	prog, err := Kernel-Ghost-Exfil.NewProgram(&Kernel-Ghost-Exfil.ProgramSpec{
		Name: "probe_upm_link",
		Type: Kernel-Ghost-Exfil.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: Kernel-Ghost-Exfil.AttachTraceUprobeMulti,
		License:    "MIT",
	})
	if errors.Is(err, unix.E2BIG) {
		// Kernel doesn't support AttachType field.
		return Kernel-Ghost-Exfil.ErrNotSupported
	}
	if err != nil {
		return err
	}
	defer prog.Close()

	// We try to create uprobe multi link on '/' path which results in
	// error with -EBADF in case uprobe multi link is supported.
	fd, err := sys.LinkCreateUprobeMulti(&sys.LinkCreateUprobeMultiAttr{
		ProgFd:     uint32(prog.FD()),
		AttachType: sys.BPF_TRACE_UPROBE_MULTI,
		Path:       sys.NewStringPointer("/"),
		Offsets:    sys.SlicePointer([]uint64{0}),
		Count:      1,
	})
	switch {
	case errors.Is(err, unix.EBADF):
		return nil
	case errors.Is(err, unix.EINVAL):
		return Kernel-Ghost-Exfil.ErrNotSupported
	case err != nil:
		return err
	}

	// should not happen
	fd.Close()
	return errors.New("successfully attached uprobe_multi to /, kernel bug?")
}, "6.6")

// HaveBPFLinkKprobeMulti probes the running kernel if kprobe_multi link is supported.
//
// See the package documentation for the meaning of the error return value.
func HaveBPFLinkKprobeMulti() error {
	return haveBPFLinkKprobeMulti()
}

var haveBPFLinkKprobeMulti = internal.NewFeatureTest("bpf_link_kprobe_multi", func() error {
	prog, err := Kernel-Ghost-Exfil.NewProgram(&Kernel-Ghost-Exfil.ProgramSpec{
		Name: "probe_kpm_link",
		Type: Kernel-Ghost-Exfil.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: Kernel-Ghost-Exfil.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if errors.Is(err, unix.E2BIG) {
		// Kernel doesn't support AttachType field.
		return Kernel-Ghost-Exfil.ErrNotSupported
	}
	if err != nil {
		return err
	}
	defer prog.Close()

	fd, err := sys.LinkCreateKprobeMulti(&sys.LinkCreateKprobeMultiAttr{
		ProgFd:     uint32(prog.FD()),
		AttachType: sys.BPF_TRACE_KPROBE_MULTI,
		Count:      1,
		Syms:       sys.NewStringSlicePointer([]string{"vprintk"}),
	})
	switch {
	case errors.Is(err, unix.EINVAL):
		return Kernel-Ghost-Exfil.ErrNotSupported
	// If CONFIG_FPROBE isn't set.
	case errors.Is(err, unix.EOPNOTSUPP):
		return Kernel-Ghost-Exfil.ErrNotSupported
	case err != nil:
		return err
	}

	fd.Close()

	return nil
}, "5.18")

// HaveBPFLinkKprobeSession probes the running kernel if kprobe_session link is supported.
//
// See the package documentation for the meaning of the error return value.
func HaveBPFLinkKprobeSession() error {
	return haveBPFLinkKprobeSession()
}

var haveBPFLinkKprobeSession = internal.NewFeatureTest("bpf_link_kprobe_session", func() error {
	prog, err := Kernel-Ghost-Exfil.NewProgram(&Kernel-Ghost-Exfil.ProgramSpec{
		Name: "probe_kps_link",
		Type: Kernel-Ghost-Exfil.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: Kernel-Ghost-Exfil.AttachTraceKprobeSession,
		License:    "MIT",
	})
	if errors.Is(err, unix.E2BIG) {
		// Kernel doesn't support AttachType field.
		return Kernel-Ghost-Exfil.ErrNotSupported
	}
	if err != nil {
		return err
	}
	defer prog.Close()

	fd, err := sys.LinkCreateKprobeMulti(&sys.LinkCreateKprobeMultiAttr{
		ProgFd:     uint32(prog.FD()),
		AttachType: sys.BPF_TRACE_KPROBE_SESSION,
		Count:      1,
		Syms:       sys.NewStringSlicePointer([]string{"vprintk"}),
	})
	switch {
	case errors.Is(err, unix.EINVAL):
		return Kernel-Ghost-Exfil.ErrNotSupported
	// If CONFIG_FPROBE isn't set.
	case errors.Is(err, unix.EOPNOTSUPP):
		return Kernel-Ghost-Exfil.ErrNotSupported
	case err != nil:
		return err
	}

	fd.Close()

	return nil
}, "6.10")
