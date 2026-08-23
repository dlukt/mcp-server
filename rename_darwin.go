//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames fromRel -> toRel atomically on macOS using
// renameatx_np(RENAME_EXCL), which fails with EEXIST if the destination
// exists. Directory FDs are obtained through a.root, so containment is
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

	fromPtr, err := unix.BytePtrFromString(fromBase) // cleanRelPath rejects NUL bytes
	if err != nil {
		return err
	}
	toPtr, err := unix.BytePtrFromString(toBase)
	if err != nil {
		return err
	}

	n, _, errno := unix.Syscall6(
		unix.SYS_RENAMEATX_NP,
		fromDir.Fd(), uintptr(unsafe.Pointer(fromPtr)),
		toDir.Fd(), uintptr(unsafe.Pointer(toPtr)),
		unix.RENAME_EXCL, 0,
	)
	_ = n
	switch {
	case errno == 0:
		return nil
	case errors.Is(errno, syscall.ENOSYS), errors.Is(errno, syscall.EINVAL):
		// Kernel or filesystem without renameatx_np/RENAME_EXCL support:
		// refuse rather than degrade to a racy emulation.
		return fmt.Errorf("atomic no-replace rename not supported by this kernel/filesystem: %w", errors.Join(errno, errors.ErrUnsupported))
	case errors.Is(errno, fs.ErrNotExist):
		return errno
	default:
		return fmt.Errorf("renameatx_np: %w", errno)
	}
}
