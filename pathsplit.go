//go:build linux || darwin

package main

import "path/filepath"

// pathSplitLast splits rel into its parent directory (possibly ".") and
// final component, slash-normalized.
func pathSplitLast(rel string) (parent, base string) {
	parent, base = filepath.Split(rel)
	parent = filepath.ToSlash(filepath.Clean(parent))
	if parent == "/" {
		parent = "."
	}
	return parent, base
}
