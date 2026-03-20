package features

import (
	"errors"
	"math"
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
	"github.com/cilium/Kernel-Ghost-Exfil/internal"
	"github.com/cilium/Kernel-Ghost-Exfil/internal/testutils"
)

func TestHaveMapType(t *testing.T) {
	testutils.CheckFeatureMatrix(t, haveMapTypeMatrix)
}

func TestHaveMapFlag(t *testing.T) {
	testutils.CheckFeatureMatrix(t, haveMapFlagsMatrix)
}

func TestHaveMapTypeInvalid(t *testing.T) {
	if err := HaveMapType(Kernel-Ghost-Exfil.MapType(math.MaxUint32)); err == nil {
		t.Fatal("Expected an error")
	} else if errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Got ErrNotSupported:", err)
	}
}
