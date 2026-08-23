package main

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"
)

// newTestApp opens an os.Root on a fresh temp directory.
func newTestApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return &app{root: root, base: dir, cfg: Config{}}
}

// TestRenameNoReplaceBasic covers the happy path on the host platform
// (renameat2 on Linux, Link+Remove elsewhere).
func TestRenameNoReplaceBasic(t *testing.T) {
	a := newTestApp(t)
	if err := a.root.WriteFile("src.txt", []byte("data"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := a.renameNoReplace("src.txt", "dst.txt"); err != nil {
		t.Fatalf("renameNoReplace: %v", err)
	}
	if _, err := a.root.Lstat("src.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still present: %v", err)
	}
	b, err := a.root.ReadFile("dst.txt")
	if err != nil || string(b) != "data" {
		t.Fatalf("destination wrong: %q, %v", b, err)
	}
}

// TestRenameNoReplaceExistingDest verifies the no-clobber guarantee.
func TestRenameNoReplaceExistingDest(t *testing.T) {
	a := newTestApp(t)
	if err := a.root.WriteFile("src.txt", []byte("src"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.root.WriteFile("dst.txt", []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := a.renameNoReplace("src.txt", "dst.txt")
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("want fs.ErrExist, got %v", err)
	}
	b, _ := a.root.ReadFile("dst.txt")
	if string(b) != "original" {
		t.Fatalf("destination was clobbered: %q", b)
	}
	// source must survive a refused rename
	if _, err := a.root.Lstat("src.txt"); err != nil {
		t.Fatalf("source lost on refused rename: %v", err)
	}
}

// TestRenameNoReplaceNestedPaths renames across parent directories.
func TestRenameNoReplaceNestedPaths(t *testing.T) {
	a := newTestApp(t)
	if err := a.root.MkdirAll("a/b", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.root.MkdirAll("c", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.root.WriteFile("a/b/file.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.renameNoReplace("a/b/file.txt", "c/file.txt"); err != nil {
		t.Fatalf("renameNoReplace: %v", err)
	}
	if _, err := a.root.Lstat("c/file.txt"); err != nil {
		t.Fatalf("destination missing: %v", err)
	}
}

// TestRenameNoReplaceMissingDestParent verifies ENOENT propagation.
func TestRenameNoReplaceMissingDestParent(t *testing.T) {
	a := newTestApp(t)
	if err := a.root.WriteFile("src.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := a.renameNoReplace("src.txt", "nope/dst.txt")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want fs.ErrNotExist, got %v", err)
	}
}

// TestCleanRelPath covers path normalization and rejection rules.
func TestCleanRelPath(t *testing.T) {
	for in, want := range map[string]string{
		"":       ".",
		".":      ".",
		"./":     ".",
		"a":      "a",
		"a//b":   "a/b",
		"a/./b":  "a/b",
		"a/b/":   "a/b",
		" a/ b ": " a/ b ",
		"a/../b": "b",
	} {
		got, err := cleanRelPath(in)
		if err != nil || got != want {
			t.Errorf("cleanRelPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for in, want := range map[string]string{
		"/etc/passwd": "absolute",
		"/abs":        "absolute",
		"~":           "home-relative",
		"~/x":         "home-relative",
		"..":          "escape",
		"../x":        "escape",
		"a/../../x":   "escape",
		"a\u0000b":    "NUL",
	} {
		_, err := cleanRelPath(in)
		if err == nil {
			t.Errorf("cleanRelPath(%q): want error, got none", in)
			continue
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Errorf("cleanRelPath(%q) error %q does not mention %q", in, err, want)
		}
	}
}

// TestIsPrivateIP covers the private-IP classification.
func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.1.1", "100.64.0.1", "100.127.255.255", "255.255.255.255",
		"::1", "fc00::1", "fd12:3456:789a::1", "fe80::1", "::ffff:127.0.0.1",
		"::ffff:10.0.0.1", "0.0.0.0",
	}
	public := []string{
		"1.1.1.1", "8.8.8.8", "172.32.0.1", "172.15.255.255", "100.0.0.1",
		"100.128.0.1", "64.0.0.1", "2001:4860::8888", "::ffff:8.8.8.8",
		"2606:4700::1111",
	}
	for _, s := range private {
		if !isPrivateIP(net.ParseIP(s)) {
			t.Errorf("isPrivateIP(%s) = false, want true", s)
		}
	}
	for _, s := range public {
		if isPrivateIP(net.ParseIP(s)) {
			t.Errorf("isPrivateIP(%s) = true, want false", s)
		}
	}
}
