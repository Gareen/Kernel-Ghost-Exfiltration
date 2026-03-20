//go:build !windows

package link

import (
	"net"
	"testing"

	"github.com/cilium/Kernel-Ghost-Exfil"
)

func TestSocketFilterAttach(t *testing.T) {
	prog := mustLoadProgram(t, Kernel-Ghost-Exfil.SocketFilter, 0, "")

	defer prog.Close()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := AttachSocketFilter(conn, prog); err != nil {
		t.Fatal(err)
	}

	if err := DetachSocketFilter(conn); err != nil {
		t.Fatal(err)
	}
}
