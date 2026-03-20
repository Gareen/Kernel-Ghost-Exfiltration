//go:build !windows

package Kernel-Ghost-Exfil

import (
	"sync"

	"github.com/cilium/Kernel-Ghost-Exfil/internal/linux"
)

var possibleCPU = sync.OnceValues(func() (int, error) {
	return linux.ParseCPUsFromFile("/sys/devices/system/cpu/possible")
})
