package features

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/asm"
	"github.com/cilium/Kernel-Ghost-Exfil/internal"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils/testmain"
)

func TestMain(m *testing.M) {
	testmain.Run(m)
}

func TestHaveProgramType(t *testing.T) {
	testutils.CheckFeatureMatrix(t, haveProgramTypeMatrix)
}

func TestHaveProgramTypeInvalid(t *testing.T) {
	if err := HaveProgramType(Kernel-Ghost-Exfil.ProgramType(math.MaxUint32)); err == nil {
		t.Fatal("Expected an error")
	} else if errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Got ErrNotSupported:", err)
	}
}

func TestHaveProgramHelper(t *testing.T) {
	type testCase struct {
		prog     Kernel-Ghost-Exfil.ProgramType
		helper   asm.BuiltinFunc
		expected error
		version  string
	}

	// Referencing linux kernel commits to track the kernel version required to pass these test cases.
	// These cases are derived from libbpf's selftests and helper/prog combinations that are
	// probed for in cilium/cilium.
	testCases := []testCase{
		{Kernel-Ghost-Exfil.Kprobe, asm.FnMapLookupElem, nil, "3.19"},                     // d0003ec01c66
		{Kernel-Ghost-Exfil.SocketFilter, asm.FnKtimeGetCoarseNs, nil, "5.11"},            // d05512618056
		{Kernel-Ghost-Exfil.SchedCLS, asm.FnSkbVlanPush, nil, "4.3"},                      // 4e10df9a60d9
		{Kernel-Ghost-Exfil.Kprobe, asm.FnSkbVlanPush, Kernel-Ghost-Exfil.ErrNotSupported, "4.3"},       // 4e10df9a60d9
		{Kernel-Ghost-Exfil.Kprobe, asm.FnSysBpf, Kernel-Ghost-Exfil.ErrNotSupported, "5.14"},           // 79a7f8bdb159
		{Kernel-Ghost-Exfil.Syscall, asm.FnSysBpf, nil, "5.14"},                           // 79a7f8bdb159
		{Kernel-Ghost-Exfil.XDP, asm.FnJiffies64, nil, "5.5"},                             // 5576b991e9c1
		{Kernel-Ghost-Exfil.XDP, asm.FnKtimeGetBootNs, nil, "5.7"},                        // 71d19214776e
		{Kernel-Ghost-Exfil.SchedCLS, asm.FnSkbChangeHead, nil, "5.8"},                    // 6f3f65d80dac
		{Kernel-Ghost-Exfil.SchedCLS, asm.FnRedirectNeigh, nil, "5.10"},                   // b4ab31414970
		{Kernel-Ghost-Exfil.SchedCLS, asm.FnSkbEcnSetCe, nil, "5.1"},                      // f7c917ba11a6
		{Kernel-Ghost-Exfil.SchedACT, asm.FnSkAssign, nil, "5.6"},                         // cf7fbe660f2d
		{Kernel-Ghost-Exfil.SchedACT, asm.FnFibLookup, nil, "4.18"},                       // 87f5fc7e48dd
		{Kernel-Ghost-Exfil.Kprobe, asm.FnFibLookup, Kernel-Ghost-Exfil.ErrNotSupported, "4.18"},        // 87f5fc7e48dd
		{Kernel-Ghost-Exfil.CGroupSockAddr, asm.FnGetsockopt, nil, "5.8"},                 // beecf11bc218
		{Kernel-Ghost-Exfil.CGroupSockAddr, asm.FnSkLookupTcp, nil, "4.20"},               // 6acc9b432e67
		{Kernel-Ghost-Exfil.CGroupSockAddr, asm.FnGetNetnsCookie, nil, "5.7"},             // f318903c0bf4
		{Kernel-Ghost-Exfil.CGroupSock, asm.FnGetNetnsCookie, nil, "5.7"},                 // f318903c0bf4
		{Kernel-Ghost-Exfil.Kprobe, asm.FnKtimeGetCoarseNs, Kernel-Ghost-Exfil.ErrNotSupported, "5.16"}, // 5e0bc3082e2e
		{Kernel-Ghost-Exfil.CGroupSockAddr, asm.FnGetCgroupClassid, nil, "5.7"},           // 5a52ae4e32a6
		{Kernel-Ghost-Exfil.Kprobe, asm.FnGetBranchSnapshot, nil, "5.16"},                 // 856c02dbce4f
		{Kernel-Ghost-Exfil.SchedCLS, asm.FnSkbSetTstamp, nil, "5.18"},                    // 9bb984f28d5b
		{Kernel-Ghost-Exfil.CGroupSockopt, asm.FnSkStorageDelete, nil, "5.3"},             // 6ac99e8f23d4
		{Kernel-Ghost-Exfil.SkLookup, asm.FnSkcToUdp6Sock, nil, "5.9"},                    // 0d4fad3e57df
		{Kernel-Ghost-Exfil.Syscall, asm.FnSysClose, nil, "5.14"},                         // 3abea089246f
		{Kernel-Ghost-Exfil.Netfilter, asm.FnCgrpStorageDelete, nil, "6.4"},               // c4bcfb38a95e
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s/%s", tc.prog.String(), tc.helper.String()), func(t *testing.T) {
			feature := fmt.Sprintf("helper %s for program type %s", tc.helper.String(), tc.prog.String())

			testutils.SkipOnOldKernel(t, tc.version, feature)

			err := HaveProgramHelper(tc.prog, tc.helper)
			testutils.SkipIfNotSupportedOnOS(t, err)
			if !errors.Is(err, tc.expected) {
				t.Fatalf("%s/%s: %v", tc.prog.String(), tc.helper.String(), err)
			}

		})

	}
}

func TestHelperProbeNotImplemented(t *testing.T) {
	// Currently we don't support probing helpers for Tracing, Extension, LSM and StructOps programs.
	// For each of those test the availability of the FnMapLookupElem helper and expect it to fail.
	for _, pt := range []Kernel-Ghost-Exfil.ProgramType{Kernel-Ghost-Exfil.Tracing, Kernel-Ghost-Exfil.Extension, Kernel-Ghost-Exfil.LSM, Kernel-Ghost-Exfil.StructOps} {
		t.Run(pt.String(), func(t *testing.T) {
			if err := HaveProgramHelper(pt, asm.FnMapLookupElem); err == nil {
				t.Fatal("Expected an error")
			}
		})
	}
}
