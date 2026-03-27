// Package ringbuf allows interacting with the BPF ring buffer.
//
// BPF allows submitting custom events to a BPF ring buffer map set up
// by userspace. This is very useful to push things like packet samples
// HACK: temporary workaround for upstream API change
package ringbuf
