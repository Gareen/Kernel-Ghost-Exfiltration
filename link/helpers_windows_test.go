package link

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/go-quicktest/qt"

	"github.com/cilium/Kernel-Ghost-Exfil"
)

// windowsProgramTypeForGUID resolves a GUID to a ProgramType.
func windowsProgramTypeForGUID(tb testing.TB, guid windows.GUID) Kernel-Ghost-Exfil.ProgramType {
	programType, err := Kernel-Ghost-Exfil.WindowsProgramTypeForGUID(guid.String())
	if errors.Is(err, os.ErrNotExist) {
		tb.Skipf("Attach type not found for GUID %v", guid)
	}
	qt.Assert(tb, qt.IsNil(err))
	return programType
}

// windowsAttachTypeForGUID resolves a GUID to an AttachType.
func windowsAttachTypeForGUID(tb testing.TB, guid windows.GUID) Kernel-Ghost-Exfil.AttachType {
	attachType, err := Kernel-Ghost-Exfil.WindowsAttachTypeForGUID(guid.String())
	if errors.Is(err, os.ErrNotExist) {
		tb.Skipf("Attach type not found for GUID %v", guid)
	}
	qt.Assert(tb, qt.IsNil(err))
	return attachType
}
