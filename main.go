// mcp-fileserver: a sandboxed MCP server exposing file CRUD (and HTTP fetch)
// inside a single base directory tree.
//
// Containment is enforced by os.Root (Linux openat2 RESOLVE_BENEATH), so
// symlinks cannot escape the base directory, and by a dial-time IP guard for
// the http_request tool, so redirects and DNS rebinding cannot reach private
// networks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const serverVersion = "0.4.0"

// Config holds runtime configuration for the server.
type Config struct {
	BaseDir        string
	AllowOverwrite bool
	MaxFileBytes   int64
}

// app carries the sandbox root and config into tool handlers via context.
type app struct {
	root *os.Root
	base string
	cfg  Config
}

type ctxKeyApp struct{}

func appFrom(ctx context.Context) *app {
	return ctx.Value(ctxKeyApp{}).(*app)
}

func main() {
	cfg := parseFlags()

	baseAbs, err := filepath.Abs(cfg.BaseDir)
	checkFatal(err)
	info, err := os.Stat(baseAbs)
	if err != nil {
		checkFatal(fmt.Errorf("base directory error: %w", err))
	}
	if !info.IsDir() {
		checkFatal(fmt.Errorf("base path is not a directory: %s", baseAbs))
	}

	// Kernel-enforced sandbox: every FS operation below goes through root.
	root, err := os.OpenRoot(baseAbs)
	checkFatal(err)
	defer root.Close()

	a := &app{root: root, base: baseAbs, cfg: cfg}

	s := server.NewMCPServer(
		"mcp-fileserver",
		serverVersion,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// ===== Tools =====

	// fs_list
	listTool := mcp.NewTool(
		"fs_list",
		mcp.WithDescription("List files and directories under the configured base directory. Returns relative paths; directories end with '/'."),
		mcp.WithString("path",
			mcp.Description("Relative subpath to list from (default '.')"),
		),
		mcp.WithBoolean("recursive",
			mcp.Description("Recurse into subdirectories (default false). Does not descend through symlinks."),
		),
		mcp.WithString("pattern",
			mcp.Description("Optional glob (e.g. '*.go') matched against the entry name; applies to files and directories"),
		),
		mcp.WithNumber("maxEntries",
			mcp.Description("Stop listing after this many entries (default 0 = unlimited)"),
		),
	)
	s.AddTool(listTool, handleList)

	// fs_read
	readTool := mcp.NewTool(
		"fs_read",
		mcp.WithDescription("Read a text file under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of file to read")),
		mcp.WithNumber("maxBytes", mcp.Description("Maximum bytes to read; default unlimited")),
	)
	s.AddTool(readTool, handleRead)

	// fs_stat
	statTool := mcp.NewTool(
		"fs_stat",
		mcp.WithDescription("Stat a file or directory under the base directory (size, mode, mtime, symlink target)."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path to stat")),
	)
	s.AddTool(statTool, handleStat)

	// fs_create
	createTool := mcp.NewTool(
		"fs_create",
		mcp.WithDescription("Create a new file with given content under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of the file to create")),
		mcp.WithString("content", mcp.Description("File contents as UTF-8 text")),
		mcp.WithBoolean("overwrite", mcp.Description("Allow overwriting if file exists (default false; server must also be started with --allow-overwrite)")),
		mcp.WithBoolean("makedirs", mcp.Description("Create parent directories as needed (default true)")),
	)
	s.AddTool(createTool, handleCreate)

	// fs_update
	updateTool := mcp.NewTool(
		"fs_update",
		mcp.WithDescription("Replace the contents of an existing file under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of the file to update")),
		mcp.WithString("content", mcp.Required(), mcp.Description("New file contents as UTF-8 text")),
		mcp.WithBoolean("create", mcp.Description("Create the file if missing (default false)")),
	)
	s.AddTool(updateTool, handleUpdate)

	// fs_delete
	deleteTool := mcp.NewTool(
		"fs_delete",
		mcp.WithDescription("Delete a file (or symlink: the link itself) under the base directory. Directories require recursive=true."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path to delete")),
		mcp.WithBoolean("recursive", mcp.Description("Allow deleting a directory and all its contents (default false)")),
	)
	s.AddTool(deleteTool, handleDelete)

	// fs_mkdir
	mkdirTool := mcp.NewTool(
		"fs_mkdir",
		mcp.WithDescription("Create a directory under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of the directory to create")),
		mcp.WithBoolean("parents", mcp.Description("Create missing parent directories (default true). With parents=true an existing directory is not an error.")),
	)
	s.AddTool(mkdirTool, handleMkdir)

	// fs_rename
	renameTool := mcp.NewTool(
		"fs_rename",
		mcp.WithDescription("Rename/move a file or directory under the base directory. Fails if the destination exists."),
		mcp.WithString("from", mcp.Required(), mcp.Description("Relative path of the source")),
		mcp.WithString("to", mcp.Required(), mcp.Description("Relative path of the destination")),
		mcp.WithBoolean("makedirs", mcp.Description("Create missing parent directories of the destination (default true)")),
	)
	s.AddTool(renameTool, handleRename)

	// http_request
	httpTool := mcp.NewTool(
		"http_request",
		mcp.WithDescription("Perform an HTTP(S) request and return status, headers, and a (possibly truncated) body preview. Connections to localhost/private networks are blocked at dial time (covering redirects and DNS rebinding); set allowPrivate=true to override. Env proxies are ignored."),
		mcp.WithString("method", mcp.Required(), mcp.Description("HTTP method, e.g. GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")),
		mcp.WithString("url", mcp.Required(), mcp.Description("Absolute URL (http or https)")),
		mcp.WithString("headers", mcp.Description(`Optional JSON object of request headers, e.g. '{"Accept":"application/json"}'`)),
		mcp.WithString("body", mcp.Description("Optional request body (sent as-is)")),
		mcp.WithNumber("timeoutSec", mcp.Description("Request timeout in seconds (default 20)")),
		mcp.WithBoolean("followRedirects", mcp.Description("Follow redirects (default true, max 10 hops)")),
		mcp.WithNumber("maxBytes", mcp.Description("Max response bytes to return (default unlimited). Large bodies will blow up the caller's context — set a limit.")),
		mcp.WithBoolean("allowPrivate", mcp.Description("Allow connections to localhost/private networks (default false)")),
	)
	s.AddTool(httpTool, handleHTTPRequest)

	// Serve over stdio and inject the app into the request context.
	if err := server.ServeStdio(s, server.WithStdioContextFunc(func(ctx context.Context) context.Context {
		return context.WithValue(ctx, ctxKeyApp{}, a)
	})); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// ---------- Tool handlers ----------

type listResult struct {
	Base      string   `json:"base"`
	Root      string   `json:"root"`
	Paths     []string `json:"paths"`
	Count     int      `json:"count"`
	Truncated bool     `json:"truncated"`
	TookMs    int64    `json:"tookMs"`
}

var errStopWalk = errors.New("max entries reached")

func handleList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	start := time.Now()
	rel, err := cleanRelPath(req.GetString("path", "."))
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	recursive := req.GetBool("recursive", false)
	pattern := strings.TrimSpace(req.GetString("pattern", ""))
	maxEntries := req.GetInt("maxEntries", 0)

	if pattern != "" {
		if _, perr := filepath.Match(pattern, "probe"); perr != nil {
			return mcp.NewToolResultErrorf("invalid pattern: %v", perr), nil
		}
	}

	st, err := a.root.Stat(rel)
	if err != nil {
		return mcp.NewToolResultErrorf("list failed: %v", err), nil
	}
	if !st.IsDir() {
		return mcp.NewToolResultErrorf("not a directory: %s", rel), nil
	}

	out := []string{}
	truncated := false

	// listDir appends entries of dirRel (sorted, as returned by ReadDir).
	// Symlinks are listed but never descended into.
	var listDir func(dirRel string) error
	listDir = func(dirRel string) error {
		f, err := a.root.Open(dirRel)
		if err != nil {
			return err
		}
		entries, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			childRel := name
			if dirRel != "." {
				childRel = dirRel + "/" + name
			}
			isDir := e.IsDir()
			if pattern == "" {
				out = append(out, childRel+dirSuffix(isDir))
			} else if match, merr := filepath.Match(pattern, name); merr != nil {
				return merr
			} else if match {
				out = append(out, childRel+dirSuffix(isDir))
			}
			if maxEntries > 0 && len(out) >= maxEntries {
				truncated = true
				return errStopWalk
			}
			if isDir && recursive {
				if err := listDir(childRel); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := listDir(rel); err != nil && !errors.Is(err, errStopWalk) {
		return mcp.NewToolResultErrorf("list failed: %v", err), nil
	}

	res := listResult{
		Base:      a.base,
		Root:      rel,
		Paths:     out,
		Count:     len(out),
		Truncated: truncated,
		TookMs:    time.Since(start).Milliseconds(),
	}
	msg := fmt.Sprintf("%d items under %s", res.Count, res.Root)
	if truncated {
		msg += " (truncated at maxEntries)"
	}
	return mcp.NewToolResultStructured(res, msg), nil
}

func dirSuffix(isDir bool) string {
	if isDir {
		return "/"
	}
	return ""
}

func handleRead(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	p, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	maxBytes := req.GetInt("maxBytes", 0)
	rel, err := cleanRelPath(p)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	b, err := a.root.ReadFile(rel)
	if err != nil {
		return mcp.NewToolResultErrorf("read failed: %v", err), nil
	}
	if maxBytes > 0 && len(b) > maxBytes {
		b = b[:maxBytes]
	}
	preview := string(b)
	if !utf8.ValidString(preview) {
		preview = strings.ToValidUTF8(preview, "\uFFFD")
	}
	payload := struct {
		Path    string `json:"path"`
		Bytes   int    `json:"bytes"`
		Preview string `json:"preview"`
	}{
		Path:    rel,
		Bytes:   len(b),
		Preview: preview,
	}
	return mcp.NewToolResultStructured(payload, fmt.Sprintf("read %d bytes from %s", len(b), rel)), nil
}

func handleStat(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	p, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	rel, err := cleanRelPath(p)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	lst, err := a.root.Lstat(rel)
	if err != nil {
		return mcp.NewToolResultErrorf("stat failed: %v", err), nil
	}
	isSymlink := lst.Mode()&fs.ModeSymlink != 0
	// Follow the symlink for target info, but tolerate links that dangle or
	// point outside the root: reporting the link itself is safe and useful.
	st := lst
	broken := false
	if isSymlink {
		if s2, err2 := a.root.Stat(rel); err2 == nil {
			st = s2
		} else {
			broken = true
		}
	}
	var target string
	if isSymlink {
		if t, terr := a.root.Readlink(rel); terr == nil {
			target = t
		}
	}
	payload := struct {
		Path          string `json:"path"`
		Size          int64  `json:"size"`
		Mode          string `json:"mode"`
		IsDir         bool   `json:"isDir"`
		IsSymlink     bool   `json:"isSymlink"`
		SymlinkTarget string `json:"symlinkTarget,omitempty"`
		Broken        bool   `json:"broken,omitempty"`
		ModTime       string `json:"modTime"`
	}{
		Path:      rel,
		Size:      st.Size(),
		Mode:      st.Mode().String(),
		IsDir:     st.IsDir(),
		IsSymlink: isSymlink,
		Broken:    broken,
		ModTime:   st.ModTime().UTC().Format(time.RFC3339),
	}
	if target != "" {
		payload.SymlinkTarget = target
	}
	kind := "file"
	if payload.IsDir {
		kind = "dir"
	}
	if isSymlink {
		kind = "symlink"
	}
	if broken {
		kind += " (unresolvable)"
	}
	return mcp.NewToolResultStructured(payload, fmt.Sprintf("%s %s (%s)", rel, kind, payload.Mode)), nil
}

type createArgs struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Overwrite *bool  `json:"overwrite,omitempty"`
	Makedirs  *bool  `json:"makedirs,omitempty"`
}

type fileResult struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Bytes  int    `json:"bytes"`
}

func handleCreate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)

	var args createArgs
	if err := req.BindArguments(&args); err != nil {
		return mcp.NewToolResultErrorf("invalid arguments: %v", err), nil
	}
	if args.Path == "" {
		return mcp.NewToolResultError("'path' is required"), nil
	}
	makedirs := args.Makedirs == nil || *args.Makedirs
	overwrite := args.Overwrite != nil && *args.Overwrite

	rel, err := cleanRelPath(args.Path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if rel == "." {
		return mcp.NewToolResultError("path must name a file, not the base directory"), nil
	}
	if err := a.checkSize(len(args.Content)); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if makedirs {
		if err := a.root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
			return mcp.NewToolResultErrorf("mkdirs failed: %v", err), nil
		}
	}

	action := "created"
	flagSet := os.O_WRONLY | os.O_CREATE
	if overwrite {
		if !a.cfg.AllowOverwrite {
			return mcp.NewToolResultError("overwrite requested but server was started with --allow-overwrite=false"), nil
		}
		flagSet |= os.O_TRUNC
		action = "overwritten"
	} else {
		flagSet |= os.O_EXCL
	}

	f, err := a.root.OpenFile(rel, flagSet, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return mcp.NewToolResultError("file exists; pass overwrite=true (server must allow it)"), nil
		}
		return mcp.NewToolResultErrorf("create failed: %v", err), nil
	}
	if _, err := f.WriteString(args.Content); err != nil {
		f.Close()
		return mcp.NewToolResultErrorf("write failed: %v", err), nil
	}
	if err := f.Close(); err != nil {
		return mcp.NewToolResultErrorf("close failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: rel, Action: action, Bytes: len(args.Content)}, action), nil
}

func handleUpdate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	content, err := req.RequireString("content")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	create := req.GetBool("create", false)

	rel, err := cleanRelPath(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if rel == "." {
		return mcp.NewToolResultError("path must name a file, not the base directory"), nil
	}
	if err := a.checkSize(len(content)); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	flagSet := os.O_WRONLY | os.O_TRUNC
	if create {
		flagSet |= os.O_CREATE
		if err := a.root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
			return mcp.NewToolResultErrorf("mkdirs failed: %v", err), nil
		}
	}

	f, err := a.root.OpenFile(rel, flagSet, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !create {
			return mcp.NewToolResultError("file does not exist; pass create=true to create it"), nil
		}
		return mcp.NewToolResultErrorf("update failed: %v", err), nil
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return mcp.NewToolResultErrorf("write failed: %v", err), nil
	}
	if err := f.Close(); err != nil {
		return mcp.NewToolResultErrorf("close failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: rel, Action: "updated", Bytes: len(content)}, "updated"), nil
}

func handleDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	p, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	recursive := req.GetBool("recursive", false)

	rel, err := cleanRelPath(p)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if rel == "." {
		return mcp.NewToolResultError("refusing to delete the base directory"), nil
	}

	st, err := a.root.Lstat(rel) // lstat: symlinks are deleted as links
	if err != nil {
		return mcp.NewToolResultErrorf("delete failed: %v", err), nil
	}
	if st.IsDir() {
		if !recursive {
			return mcp.NewToolResultError("refusing to delete a directory; pass recursive=true"), nil
		}
		if err := a.root.RemoveAll(rel); err != nil {
			return mcp.NewToolResultErrorf("delete failed: %v", err), nil
		}
	} else if err := a.root.Remove(rel); err != nil {
		return mcp.NewToolResultErrorf("delete failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: rel, Action: "deleted"}, "deleted"), nil
}

func handleMkdir(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	p, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	parents := req.GetBool("parents", true)

	rel, err := cleanRelPath(p)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if rel == "." {
		return mcp.NewToolResultError("directory already exists: ."), nil
	}

	if parents {
		if err := a.root.MkdirAll(rel, 0o755); err != nil {
			return mcp.NewToolResultErrorf("mkdir failed: %v", err), nil
		}
	} else if err := a.root.Mkdir(rel, 0o755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return mcp.NewToolResultError("directory already exists; use parents=true to tolerate"), nil
		}
		return mcp.NewToolResultErrorf("mkdir failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: rel, Action: "created"}, fmt.Sprintf("created directory %s", rel)), nil
}

func handleRename(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := appFrom(ctx)
	from, err := req.RequireString("from")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	to, err := req.RequireString("to")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	makedirs := req.GetBool("makedirs", true)

	fromRel, err := cleanRelPath(from)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	toRel, err := cleanRelPath(to)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if fromRel == "." || toRel == "." {
		return mcp.NewToolResultError("cannot rename the base directory"), nil
	}
	if _, err := a.root.Lstat(fromRel); err != nil {
		return mcp.NewToolResultErrorf("rename failed: source not found: %v", err), nil
	}
	if _, err := a.root.Lstat(toRel); err == nil {
		return mcp.NewToolResultError("destination exists; delete it first"), nil
	}
	if makedirs {
		if err := a.root.MkdirAll(filepath.Dir(toRel), 0o755); err != nil {
			return mcp.NewToolResultErrorf("mkdirs failed: %v", err), nil
		}
	}
	if err := a.renameNoReplace(fromRel, toRel); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return mcp.NewToolResultError("destination exists; delete it first"), nil
		}
		return mcp.NewToolResultErrorf("rename failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(
		struct {
			From string `json:"from"`
			To   string `json:"to"`
		}{From: fromRel, To: toRel},
		fmt.Sprintf("renamed %s -> %s", fromRel, toRel),
	), nil
}

// ---------- HTTP tool handler ----------

type httpResult struct {
	URL         string              `json:"url"`
	Method      string              `json:"method"`
	Status      string              `json:"status"`
	StatusCode  int                 `json:"statusCode"`
	Headers     map[string][]string `json:"headers"`
	Bytes       int                 `json:"bytes"`
	Truncated   bool                `json:"truncated"`
	BodyPreview string              `json:"bodyPreview"`
}

func handleHTTPRequest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	method, err := req.RequireString("method")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	rawURL, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return mcp.NewToolResultError("method is required"), nil
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return mcp.NewToolResultError("invalid url"), nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return mcp.NewToolResultError("only http and https are allowed"), nil
	}

	allowPrivate := req.GetBool("allowPrivate", false)

	// Dial-time guard: validated for every TCP connection the client makes,
	// which covers redirects and defeats DNS rebinding between check and dial.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("non-IP dial address %q", address)
			}
			if isPrivateIP(ip) {
				return fmt.Errorf("connection to private/localhost address %s blocked (allowPrivate=true to override)", ip)
			}
			return nil
		},
	}
	// Never use env proxies: a proxy would fetch on our behalf and bypass
	// the dial-time guard entirely.
	transport := &http.Transport{DialContext: dialer.DialContext}

	headersJSON := strings.TrimSpace(req.GetString("headers", ""))
	headers := map[string]string{}
	if headersJSON != "" {
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return mcp.NewToolResultErrorf("invalid headers JSON: %v", err), nil
		}
	}

	body := req.GetString("body", "")
	timeoutSec := req.GetInt("timeoutSec", 20)
	if timeoutSec <= 0 {
		timeoutSec = 20
	}
	maxBytes := req.GetInt("maxBytes", 0)
	follow := req.GetBool("followRedirects", true)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	client := &http.Client{Transport: transport}
	if !follow {
		client.CheckRedirect = func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	} else {
		// Extend (not replace) the default policy: http(s) only, and keep the
		// stdlib's ten-hop limit so cyclic redirect chains can't run until
		// the overall timeout. IP validation happens at dial time.
		client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-http(s) scheme blocked: %s", r.URL.Scheme)
			}
			return nil
		}
	}
	// The transport is per-request (its dial guard captures allowPrivate);
	// it is never reused, so release its idle connections when done instead
	// of accumulating sockets (and their read goroutines) across calls.
	defer transport.CloseIdleConnections()

	httpReq, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
	if err != nil {
		return mcp.NewToolResultErrorf("request build failed: %v", err), nil
	}
	httpReq.Header.Set("User-Agent", "mcp-fileserver/"+serverVersion)
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return mcp.NewToolResultErrorf("request failed: %v", err), nil
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, int64(maxBytes)+1)
	}
	b, _ := io.ReadAll(reader)

	trunc := false
	if maxBytes > 0 && len(b) > maxBytes {
		trunc = true
		b = b[:maxBytes]
	}

	preview := string(b)
	if !utf8.ValidString(preview) {
		preview = strings.ToValidUTF8(preview, "\uFFFD")
	}

	res := httpResult{
		URL:         u.String(),
		Method:      method,
		Status:      resp.Status,
		StatusCode:  resp.StatusCode,
		Headers:     resp.Header,
		Bytes:       len(b),
		Truncated:   trunc,
		BodyPreview: preview,
	}
	msg := fmt.Sprintf("%s %s → %d (%d bytes)%s",
		method, u.Host, res.StatusCode, res.Bytes,
		map[bool]string{true: " [truncated]", false: ""}[trunc],
	)
	return mcp.NewToolResultStructured(res, msg), nil
}

// ---------- helpers ----------

func (a *app) checkSize(n int) error {
	if a.cfg.MaxFileBytes > 0 && int64(n) > a.cfg.MaxFileBytes {
		return fmt.Errorf("content too large: %d bytes (limit %d)", n, a.cfg.MaxFileBytes)
	}
	return nil
}

// isPrivateIP reports whether ip is a loopback, link-local, multicast,
// unspecified, broadcast, RFC1918, unique-local, CGNAT, or IPv4-mapped
// private address.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 255.255.255.255 broadcast
		if v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
			return true
		}
		// 100.64.0.0/10 CGNAT shared address space (e.g. Tailscale)
		return v4[0] == 100 && v4[1]&0xC0 == 64
	}
	return false
}

// cleanRelPath normalizes a user-supplied relative path for use with os.Root.
// Absolute paths and traversal outside the base are rejected up front for a
// clear error message (os.Root would reject them anyway). Whitespace is
// significant and preserved: trimming would silently redirect "x.txt"
// requests to a different file.
func cleanRelPath(rel string) (string, error) {
	if rel == "" {
		return ".", nil
	}
	if strings.ContainsRune(rel, 0) {
		return "", errors.New("path contains NUL byte")
	}
	if os.IsPathSeparator(rel[0]) {
		return "", errors.New("absolute paths are not allowed; use a path relative to the base directory")
	}
	if rel[0] == '~' && (len(rel) == 1 || os.IsPathSeparator(rel[1])) {
		return "", errors.New("home-relative paths are not allowed; use a path relative to the base directory")
	}
	p := filepath.ToSlash(filepath.Clean(rel))
	if p == "." {
		return ".", nil
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", errors.New("path escapes base directory")
	}
	return p, nil
}

func parseFlags() Config {
	var cfg Config
	var showVersion bool
	flag.StringVar(&cfg.BaseDir, "base", ".", "Base directory the server will expose")
	flag.BoolVar(&cfg.AllowOverwrite, "allow-overwrite", false, "Permit fs_create to overwrite existing files when overwrite=true")
	flag.Int64Var(&cfg.MaxFileBytes, "max-bytes", 0, "Max bytes accepted for create/update (0 = unlimited)")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()
	if showVersion {
		fmt.Printf("mcp-fileserver %s\n", serverVersion)
		os.Exit(0)
	}
	return cfg
}

func checkFatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
