package features

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/asm"
	"github.com/cilium/Kernel-Ghost-Exfil/btf"
	"github.com/cilium/Kernel-Ghost-Exfil/internal"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/sys"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/unix"
)

// HaveProgramType probes the running kernel for the availability of the specified program type.
//
// See the package documentation for the meaning of the error return value.
func HaveProgramType(pt Kernel-Ghost-Exfil.ProgramType) (err error) {
	return haveProgramTypeMatrix.Result(pt)
}

func probeProgram(spec *Kernel-Ghost-Exfil.ProgramSpec) error {
	if spec.Instructions == nil {
		spec.Instructions = asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		}
	}
	prog, err := Kernel-Ghost-Exfil.NewProgramWithOptions(spec, Kernel-Ghost-Exfil.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		prog.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = Kernel-Ghost-Exfil.ErrNotSupported
	}

	return err
}

var haveProgramTypeMatrix = internal.FeatureMatrix[Kernel-Ghost-Exfil.ProgramType]{
	Kernel-Ghost-Exfil.SocketFilter:  {Version: "3.19"},
	Kernel-Ghost-Exfil.Kprobe:        {Version: "4.1"},
	Kernel-Ghost-Exfil.SchedCLS:      {Version: "4.1"},
	Kernel-Ghost-Exfil.SchedACT:      {Version: "4.1"},
	Kernel-Ghost-Exfil.TracePoint:    {Version: "4.7"},
	Kernel-Ghost-Exfil.XDP:           {Version: "4.8"},
	Kernel-Ghost-Exfil.PerfEvent:     {Version: "4.9"},
	Kernel-Ghost-Exfil.CGroupSKB:     {Version: "4.10"},
	Kernel-Ghost-Exfil.CGroupSock:    {Version: "4.10"},
	Kernel-Ghost-Exfil.LWTIn:         {Version: "4.10"},
	Kernel-Ghost-Exfil.LWTOut:        {Version: "4.10"},
	Kernel-Ghost-Exfil.LWTXmit:       {Version: "4.10"},
	Kernel-Ghost-Exfil.SockOps:       {Version: "4.13"},
	Kernel-Ghost-Exfil.SkSKB:         {Version: "4.14"},
	Kernel-Ghost-Exfil.CGroupDevice:  {Version: "4.15"},
	Kernel-Ghost-Exfil.SkMsg:         {Version: "4.17"},
	Kernel-Ghost-Exfil.RawTracepoint: {Version: "4.17"},
	Kernel-Ghost-Exfil.CGroupSockAddr: {
		Version: "4.17",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:       Kernel-Ghost-Exfil.CGroupSockAddr,
				AttachType: Kernel-Ghost-Exfil.AttachCGroupInet4Connect,
			})
		},
	},
	Kernel-Ghost-Exfil.LWTSeg6Local:          {Version: "4.18"},
	Kernel-Ghost-Exfil.LircMode2:             {Version: "4.18"},
	Kernel-Ghost-Exfil.SkReuseport:           {Version: "4.19"},
	Kernel-Ghost-Exfil.FlowDissector:         {Version: "4.20"},
	Kernel-Ghost-Exfil.CGroupSysctl:          {Version: "5.2"},
	Kernel-Ghost-Exfil.RawTracepointWritable: {Version: "5.2"},
	Kernel-Ghost-Exfil.CGroupSockopt: {
		Version: "5.3",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:       Kernel-Ghost-Exfil.CGroupSockopt,
				AttachType: Kernel-Ghost-Exfil.AttachCGroupGetsockopt,
			})
		},
	},
	Kernel-Ghost-Exfil.Tracing: {
		Version: "5.5",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:       Kernel-Ghost-Exfil.Tracing,
				AttachType: Kernel-Ghost-Exfil.AttachTraceFEntry,
				AttachTo:   "bpf_init",
			})
		},
	},
	Kernel-Ghost-Exfil.StructOps: {
		Version: "5.6",
		Fn: func() error {
			err := probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:    Kernel-Ghost-Exfil.StructOps,
				License: "GPL",
			})
			if errors.Is(err, sys.ENOTSUPP) {
				// ENOTSUPP means the program type is at least known to the kernel.
				return nil
			}
			return err
		},
	},
	Kernel-Ghost-Exfil.Extension: {
		Version: "5.6",
		Fn: func() error {
			// create btf.Func to add to first ins of target and extension so both progs are btf powered
			btfFn := btf.Func{
				Name: "a",
				Type: &btf.FuncProto{
					Return: &btf.Int{},
					Params: []btf.FuncParam{
						{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md"}}},
					},
				},
				Linkage: btf.GlobalFunc,
			}
			insns := asm.Instructions{
				btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0), &btfFn),
				asm.Return(),
			}

			// create target prog
			prog, err := Kernel-Ghost-Exfil.NewProgramWithOptions(
				&Kernel-Ghost-Exfil.ProgramSpec{
					Type:         Kernel-Ghost-Exfil.XDP,
					Instructions: insns,
				},
				Kernel-Ghost-Exfil.ProgramOptions{
					LogDisabled: true,
				},
			)
			if err != nil {
				return err
			}
			defer prog.Close()

			// probe for Extension prog with target
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:         Kernel-Ghost-Exfil.Extension,
				Instructions: insns,
				AttachTarget: prog,
				AttachTo:     btfFn.Name,
			})
		},
	},
	Kernel-Ghost-Exfil.LSM: {
		Version: "5.7",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:       Kernel-Ghost-Exfil.LSM,
				AttachType: Kernel-Ghost-Exfil.AttachLSMMac,
				AttachTo:   "file_mprotect",
				License:    "GPL",
			})
		},
	},
	Kernel-Ghost-Exfil.SkLookup: {
		Version: "5.9",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:       Kernel-Ghost-Exfil.SkLookup,
				AttachType: Kernel-Ghost-Exfil.AttachSkLookup,
			})
		},
	},
	Kernel-Ghost-Exfil.Syscall: {
		Version: "5.14",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:  Kernel-Ghost-Exfil.Syscall,
				Flags: sys.BPF_F_SLEEPABLE,
			})
		},
	},
	Kernel-Ghost-Exfil.Netfilter: {
		Version: "6.4",
		Fn: func() error {
			return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{
				Type:       Kernel-Ghost-Exfil.Netfilter,
				AttachType: Kernel-Ghost-Exfil.AttachNetfilter,
			})
		},
	},
}

func init() {
	for key, ft := range haveProgramTypeMatrix {
		ft.Name = key.String()
		if ft.Fn == nil {
			key := key // avoid the dreaded loop variable problem
			ft.Fn = func() error { return probeProgram(&Kernel-Ghost-Exfil.ProgramSpec{Type: key}) }
		}
	}
}

type helperKey struct {
	typ    Kernel-Ghost-Exfil.ProgramType
	helper asm.BuiltinFunc
}

var helperCache = internal.NewFeatureCache(func(key helperKey) *internal.FeatureTest {
	return &internal.FeatureTest{
		Name: fmt.Sprintf("%s for program type %s", key.helper, key.typ),
		Fn: func() error {
			return haveProgramHelper(key.typ, key.helper)
		},
	}
})

// HaveProgramHelper probes the running kernel for the availability of the specified helper
// function to a specified program type.
// Return values have the following semantics:
//
//	err == nil: The feature is available.
//	errors.Is(err, Kernel-Ghost-Exfil.ErrNotSupported): The feature is not available.
//	err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned.
// Only `nil` and `Kernel-Ghost-Exfil.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveProgramHelper(pt Kernel-Ghost-Exfil.ProgramType, helper asm.BuiltinFunc) error {
	return helperCache.Result(helperKey{pt, helper})
}

func haveProgramHelper(pt Kernel-Ghost-Exfil.ProgramType, helper asm.BuiltinFunc) error {
	if ok := helperProbeNotImplemented(pt); ok {
		return fmt.Errorf("no feature probe for %v/%v", pt, helper)
	}

	if err := HaveProgramType(pt); err != nil {
		return err
	}

	spec := &Kernel-Ghost-Exfil.ProgramSpec{
		Type: pt,
		Instructions: asm.Instructions{
			helper.Call(),
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	switch pt {
	case Kernel-Ghost-Exfil.CGroupSockAddr:
		spec.AttachType = Kernel-Ghost-Exfil.AttachCGroupInet4Connect
	case Kernel-Ghost-Exfil.CGroupSockopt:
		spec.AttachType = Kernel-Ghost-Exfil.AttachCGroupGetsockopt
	case Kernel-Ghost-Exfil.SkLookup:
		spec.AttachType = Kernel-Ghost-Exfil.AttachSkLookup
	case Kernel-Ghost-Exfil.Syscall:
		spec.Flags = sys.BPF_F_SLEEPABLE
	case Kernel-Ghost-Exfil.Netfilter:
		spec.AttachType = Kernel-Ghost-Exfil.AttachNetfilter
	}

	prog, err := Kernel-Ghost-Exfil.NewProgramWithOptions(spec, Kernel-Ghost-Exfil.ProgramOptions{
		LogLevel: 1,
	})
	if err == nil {
		prog.Close()
	}

	var verr *Kernel-Ghost-Exfil.VerifierError
	if !errors.As(err, &verr) {
		return err
	}

	helperTag := fmt.Sprintf("#%d", helper)

	switch {
	// EACCES occurs when attempting to create a program probe with a helper
	// while the register args when calling this helper aren't set up properly.
	// We interpret this as the helper being available, because the verifier
	// returns EINVAL if the helper is not supported by the running kernel.
	case errors.Is(err, unix.EACCES):
		err = nil

	// EINVAL occurs when attempting to create a program with an unknown helper.
	case errors.Is(err, unix.EINVAL):
		// https://github.com/torvalds/linux/blob/09a0fa92e5b45e99cf435b2fbf5ebcf889cf8780/kernel/bpf/verifier.c#L10663
		if logContainsAll(verr.Log, "invalid func", helperTag) {
			return Kernel-Ghost-Exfil.ErrNotSupported
		}

		// https://github.com/torvalds/linux/blob/09a0fa92e5b45e99cf435b2fbf5ebcf889cf8780/kernel/bpf/verifier.c#L10668
		wrongProgramType := logContainsAll(verr.Log, "program of this type cannot use helper", helperTag)
		// https://github.com/torvalds/linux/blob/59b418c7063d30e0a3e1f592d47df096db83185c/kernel/bpf/verifier.c#L10204
		// 4.9 doesn't include # in verifier output.
		wrongProgramType = wrongProgramType || logContainsAll(verr.Log, "unknown func")
		if wrongProgramType {
			return fmt.Errorf("program of this type cannot use helper: %w", Kernel-Ghost-Exfil.ErrNotSupported)
		}
	}

	return err
}

func logContainsAll(log []string, needles ...string) bool {
	first := max(len(log)-5, 0) // Check last 5 lines.
	return slices.ContainsFunc(log[first:], func(line string) bool {
		for _, needle := range needles {
			if !strings.Contains(line, needle) {
				return false
			}
		}
		return true
	})
}

func helperProbeNotImplemented(pt Kernel-Ghost-Exfil.ProgramType) bool {
	switch pt {
	case Kernel-Ghost-Exfil.Extension, Kernel-Ghost-Exfil.LSM, Kernel-Ghost-Exfil.StructOps, Kernel-Ghost-Exfil.Tracing:
		return true
	}
	return false
}
