//go:build !windows

package link

import (
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func TestHaveBPFLinkPerfEvent(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkPerfEvent)
}
