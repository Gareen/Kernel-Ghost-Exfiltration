//go:build !windows

package Kernel-Ghost-Exfil

import "github.com/cilium/Kernel-Ghost-Exfil/internal"

func loadCollectionFromNativeImage(_ string) (*Collection, error) {
	return nil, internal.ErrNotSupportedOnOS
}
