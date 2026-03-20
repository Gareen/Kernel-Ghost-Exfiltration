//go:build linux

package examples

import (
	"errors"
	"fmt"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/features"
)

func DocDetectXDP() {
	err := features.HaveProgramType(Kernel-Ghost-Exfil.XDP)
	if errors.Is(err, Kernel-Ghost-Exfil.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}
	if err != nil {
		// Feature detection was inconclusive.
		//
		// Note: always log and investigate these errors! These can be caused
		// by a lack of permissions, verifier errors, etc. Unless stated
		// otherwise, probes are expected to be conclusive. Please file
		// an issue if this is not the case in your environment.
		panic(err)
	}

	fmt.Println("XDP program type is supported")
}
