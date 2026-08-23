//go:build !linux

package main

import (
	"fmt"
)

// renameNoReplace renames fromRel -> toRel without clobbering an existing
// destination on non-Linux platforms, which have no portable renameat2.
//
// Files and symlinks: Link is atomic and fails with fs.ErrExist when the
// destination exists, so the no-replace guarantee holds even under
// concurrent writers; the follow-up Remove of the source is a separate
// step (a crash in between leaves both entries, but never loses data).
//
// Directories: hard links to directories are forbidden, and plain rename
// could replace a concurrently created empty destination directory, so
// atomic no-replace directory renames are simply unsupported here.
func (a *app) renameNoReplace(fromRel, toRel string) error {
	if st, err := a.root.Lstat(fromRel); err != nil {
		return err
	} else if st.IsDir() {
		return fmt.Errorf("atomic no-replace rename of directories is not supported on this platform (source is a directory)")
	}
	if err := a.root.Link(fromRel, toRel); err != nil {
		return err // fs.ErrExist when destination exists
	}
	if err := a.root.Remove(fromRel); err != nil {
		// Roll the link back so a reported failure never leaves a
		// duplicate destination behind (e.g. unwritable source parent).
		if rerr := a.root.Remove(toRel); rerr != nil {
			return fmt.Errorf("remove source: %v (rolling back destination also failed: %v)", err, rerr)
		}
		return fmt.Errorf("remove source after link (destination rolled back): %w", err)
	}
	return nil
}
