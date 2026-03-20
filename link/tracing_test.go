//go:build !windows

package link

import (
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func TestFreplace(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.10", "freplace")

	file := testutils.NativeFile(t, "../testdata/freplace-%s.elf")
	spec, err := Kernel-Ghost-Exfil.LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	target, err := Kernel-Ghost-Exfil.NewProgram(spec.Programs["sched_process_exec"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create target program:", err)
	}
	defer target.Close()

	// Test attachment specified at load time
	spec.Programs["replacement"].AttachTarget = target
	replacement, err := Kernel-Ghost-Exfil.NewProgram(spec.Programs["replacement"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create replacement program:", err)
	}
	defer replacement.Close()

	freplace, err := AttachFreplace(nil, "", replacement)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create freplace:", err)
	}

	testLink(t, freplace, replacement)
}

func TestFentryFexit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.5", "fentry")

	spec, err := Kernel-Ghost-Exfil.LoadCollectionSpec(testutils.NativeFile(t, "../testdata/fentry_fexit-%s.elf"))
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	target, err := Kernel-Ghost-Exfil.NewProgram(spec.Programs["target"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create target program:", err)
	}
	defer target.Close()

	for _, name := range []string{"trace_on_entry", "trace_on_exit"} {
		progSpec := spec.Programs[name]
		t.Run(name, func(t *testing.T) {
			progSpec.AttachTarget = target

			prog, err := Kernel-Ghost-Exfil.NewProgram(progSpec)
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()

			t.Run("link", func(t *testing.T) {
				testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

				tracingLink, err := AttachTracing(TracingOptions{
					Program: prog,
				})
				if err != nil {
					t.Fatal("Can't attach tracing:", err)
				}
				defer tracingLink.Close()

				testLink(t, tracingLink, prog)
			})

		})
	}
}

func TestTracing(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

	tests := []struct {
		name                             string
		attachTo                         string
		programType                      Kernel-Ghost-Exfil.ProgramType
		programAttachType, attachTypeOpt Kernel-Ghost-Exfil.AttachType
		cookie                           uint64
	}{
		{
			name:              "AttachTraceFEntry",
			attachTo:          "inet_dgram_connect",
			programType:       Kernel-Ghost-Exfil.Tracing,
			programAttachType: Kernel-Ghost-Exfil.AttachTraceFEntry,
		},
		{
			name:              "AttachTraceFEntry",
			attachTo:          "inet_dgram_connect",
			programType:       Kernel-Ghost-Exfil.Tracing,
			programAttachType: Kernel-Ghost-Exfil.AttachTraceFEntry,
			attachTypeOpt:     Kernel-Ghost-Exfil.AttachTraceFEntry,
			cookie:            1,
		},
		{
			name:              "AttachTraceFEntry",
			attachTo:          "inet_dgram_connect",
			programType:       Kernel-Ghost-Exfil.Tracing,
			programAttachType: Kernel-Ghost-Exfil.AttachTraceFEntry,
		},
		{
			name:              "AttachTraceFExit",
			attachTo:          "inet_dgram_connect",
			programType:       Kernel-Ghost-Exfil.Tracing,
			programAttachType: Kernel-Ghost-Exfil.AttachTraceFExit,
		},
		{
			name:              "AttachModifyReturn",
			attachTo:          "bpf_modify_return_test",
			programType:       Kernel-Ghost-Exfil.Tracing,
			programAttachType: Kernel-Ghost-Exfil.AttachModifyReturn,
		},
		{
			name:              "AttachTraceRawTp",
			attachTo:          "kfree_skb",
			programType:       Kernel-Ghost-Exfil.Tracing,
			programAttachType: Kernel-Ghost-Exfil.AttachTraceRawTp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := mustLoadProgram(t, tt.programType, tt.programAttachType, tt.attachTo)

			opts := TracingOptions{Program: prog, AttachType: tt.attachTypeOpt, Cookie: tt.cookie}
			link, err := AttachTracing(opts)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal(err)
			}
			testLink(t, link, prog)
			if err = link.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLSM(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.LSM, Kernel-Ghost-Exfil.AttachLSMMac, "file_mprotect")

	link, err := AttachLSM(LSMOptions{Program: prog})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, prog)
}
