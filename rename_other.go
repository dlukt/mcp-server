//go:build !linux

package main

// renameNoReplace on non-Linux platforms falls back to os.Root.Rename; the
// pre-check Lstat keeps the common case correct, but the no-clobber
// guarantee is only best-effort where the/windows kernels offer no atomic
// no-replace rename.
func (a *app) renameNoReplace(fromRel, toRel string) error {
	return a.root.Rename(fromRel, toRel)
}
