//go:build !linux && !darwin

package main

import (
	"errors"
	"fmt"
)

// renameNoReplace on platforms without a known atomic no-replace rename
// primitive (e.g. FreeBSD's renamedat_np is not exposed by golang.org/x/sys,
// Windows offers no handle-based equivalent through os.Root) rejects the
// operation outright: an explicit error is safer than a best-effort
// emulation whose source-unlink step can delete a concurrently replaced
// source file.
func (a *app) renameNoReplace(fromRel, toRel string) error {
	return fmt.Errorf("fs_rename: atomic no-replace rename is not supported on this platform: %w", errors.ErrUnsupported)
}
