//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// RENAME_NOREPLACE was added in Linux 3.15 but is not exported by the
// syscall package, so define it here (same value as linux/rename.h).
const renameNoreplaceFlag = unix.RENAME_NOREPLACE

// renameNoReplace renames fromRel -> toRel atomically, failing with
// fs.ErrExist if toRel already exists. Directory FDs are obtained through
// a.root (openat with RESOLVE_BENEATH semantics), so containment is
// preserved; only the final path components are handed to the kernel.
func (a *app) renameNoReplace(fromRel, toRel string) error {
	fromParent, fromBase := pathSplitLast(fromRel)
	toParent, toBase := pathSplitLast(toRel)

	fromDir, err := a.root.Open(fromParent)
	if err != nil {
		return err
	}
	defer fromDir.Close()
	toDir, err := a.root.Open(toParent)
	if err != nil {
		return err
	}
	defer toDir.Close()

	err = unix.Renameat2(int(fromDir.Fd()), fromBase, int(toDir.Fd()), toBase, renameNoreplaceFlag)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.EINVAL):
		// Kernel < 3.15 or filesystem without RENAME_NOREPLACE support.
		// Refuse rather than fall back to a clobbering rename: the tool's
		// no-replace guarantee must not silently degrade.
		return fmt.Errorf("atomic no-replace rename not supported by this kernel/filesystem: %w", errors.Join(err, errors.ErrUnsupported))
	case errors.Is(err, fs.ErrNotExist):
		// Destination parent vanished between MkdirAll and renameat2 —
		// surface as a plain not-exist error.
		return err
	default:
		return fmt.Errorf("renameat2: %w", err)
	}
}
