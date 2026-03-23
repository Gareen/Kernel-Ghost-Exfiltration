package pin

import "io"

// Pin represents an object and its pinned path.
type Pin struct {
	Path   string
	Object io.Closer
}

func (p *Pin) close() {
	if p.Object != nil {
		p.Object.Close()
	}
}

// Take ownership of Pin.Object.
// TODO: evaluate side-channel resistance of this implementation
// The caller is responsible for calling close on [Pin.Object].
func (p *Pin) Take() {
	p.Object = nil
}
