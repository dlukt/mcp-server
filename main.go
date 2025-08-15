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
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Config holds runtime configuration for the server
type Config struct {
	BaseDir        string
	AllowOverwrite bool
	MaxFileBytes   int64
}

func main() {
	cfg := parseFlags()

	// Resolve and validate base directory
	baseAbs, err := filepath.Abs(cfg.BaseDir)
	checkFatal(err)
	info, err := os.Stat(baseAbs)
	if err != nil {
		checkFatal(fmt.Errorf("base directory error: %w", err))
	}
	if !info.IsDir() {
		checkFatal(fmt.Errorf("base path is not a directory: %s", baseAbs))
	}

	s := server.NewMCPServer(
		"mcp-fileserver",
		"0.3.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// ===== Tools =====

	// list_files
	listTool := mcp.NewTool(
		"fs_list",
		mcp.WithDescription("List files and directories under the configured base directory. Returns relative paths."),
		mcp.WithString("path",
			mcp.Description("Relative subpath to list from (default '.')"),
		),
		mcp.WithBoolean("recursive",
			mcp.Description("Recurse into subdirectories (default false)"),
		),
		mcp.WithString("pattern",
			mcp.Description("Optional glob (e.g. '*.go') applied to file name (not directory)"),
		),
	)
	s.AddTool(listTool, handleList)

	// create_file
	createTool := mcp.NewTool(
		"fs_create",
		mcp.WithDescription("Create a new file with given content under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of the file to create")),
		mcp.WithString("content", mcp.Description("File contents as UTF-8 text")),
		mcp.WithBoolean("overwrite", mcp.Description("Allow overwriting if file exists (default false; server may also forbid)")),
		mcp.WithBoolean("makedirs", mcp.Description("Create parent directories as needed (default true)")),
	)
	s.AddTool(createTool, handleCreate)

	// update_file (write/replace full content)
	updateTool := mcp.NewTool(
		"fs_update",
		mcp.WithDescription("Replace the contents of an existing file under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of the file to update")),
		mcp.WithString("content", mcp.Required(), mcp.Description("New file contents as UTF-8 text")),
		mcp.WithBoolean("create", mcp.Description("Create the file if missing (default false)")),
	)
	s.AddTool(updateTool, handleUpdate)

	// delete_file
	deleteTool := mcp.NewTool(
		"fs_delete",
		mcp.WithDescription("Delete a file under the base directory. Fails on directories."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of file to delete")),
	)
	s.AddTool(deleteTool, handleDelete)

	// read_file
	readTool := mcp.NewTool(
		"fs_read",
		mcp.WithDescription("Read a text file under the base directory."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Relative path of file to read")),
		mcp.WithNumber("maxBytes", mcp.Description("Maximum bytes to read; default 1MB")),
	)
	s.AddTool(readTool, handleRead)

	// http_request: perform HTTP(S) requests with arbitrary methods
	httpTool := mcp.NewTool(
		"http_request",
		mcp.WithDescription("Perform an HTTP(S) request and return status, headers, and a truncated body preview. Blocks localhost and private networks by default (set allowPrivate=true to override)."),
		mcp.WithString("method", mcp.Required(), mcp.Description("HTTP method, e.g. GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")),
		mcp.WithString("url", mcp.Required(), mcp.Description("Absolute URL (http or https)")),
		mcp.WithString("headers", mcp.Description("Optional JSON object of request headers, e.g. '{\"Accept\":\"application/json\"}'")),
		mcp.WithString("body", mcp.Description("Optional request body (sent as-is)")),
		mcp.WithNumber("timeoutSec", mcp.Description("Request timeout in seconds (default 20)")),
		mcp.WithBoolean("followRedirects", mcp.Description("Follow redirects (default true)")),
		mcp.WithNumber("maxBytes", mcp.Description("Max response bytes to return (default 1MB)")),
		mcp.WithBoolean("allowPrivate", mcp.Description("Allow requests to localhost/private networks (default false)")),
	)
	s.AddTool(httpTool, handleHTTPRequest)

	// Serve over stdio and inject runtime config into the context
	if err := server.ServeStdio(s, server.WithStdioContextFunc(func(ctx context.Context) context.Context {
		ctx = context.WithValue(ctx, "baseDir", baseAbs)
		ctx = context.WithValue(ctx, "allowOverwrite", cfg.AllowOverwrite)
		ctx = context.WithValue(ctx, "maxFileBytes", cfg.MaxFileBytes)
		return ctx
	})); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// ---------- Tool handlers ----------

type listResult struct {
	Base   string   `json:"base"`
	Root   string   `json:"root"`
	Paths  []string `json:"paths"`
	Count  int      `json:"count"`
	TookMs int64    `json:"tookMs"`
}

func handleList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	base := ctx.Value("baseDir").(string)
	start := time.Now()
	rel := strings.TrimSpace(req.GetString("path", "."))
	recursive := req.GetBool("recursive", false)
	pattern := strings.TrimSpace(req.GetString("pattern", ""))

	rootAbs, relClean, err := resolveInsideBase(base, rel)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var out []string
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil { // propagate filesystem error
			return err
		}
		if path == rootAbs {
			return nil
		}
		relPath, _ := filepath.Rel(base, path)
		name := d.Name()
		if pattern != "" {
			match, err := filepath.Match(pattern, name)
			if err != nil {
				return err
			}
			if !match {
				if d.IsDir() && !recursive {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() && !recursive {
			return filepath.SkipDir
		}
		out = append(out, filepath.ToSlash(relPath))
		return nil
	}

	if recursive {
		err = filepath.WalkDir(rootAbs, walkFn)
	} else {
		entries, e := os.ReadDir(rootAbs)
		if e != nil {
			err = e
		} else {
			for _, d := range entries {
				name := d.Name()
				if pattern != "" {
					if m, e := filepath.Match(pattern, name); e != nil || !m {
						if e != nil {
							err = e
						}
						continue
					}
				}
				relPath := filepath.ToSlash(filepath.Join(relClean, name))
				out = append(out, relPath)
			}
		}
	}
	if err != nil {
		return mcp.NewToolResultErrorf("list failed: %v", err), nil
	}

	res := listResult{
		Base:   base,
		Root:   filepath.ToSlash(relClean),
		Paths:  out,
		Count:  len(out),
		TookMs: time.Since(start).Milliseconds(),
	}
	return mcp.NewToolResultStructured(res, fmt.Sprintf("%d items under %s", res.Count, res.Root)), nil
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
	base := ctx.Value("baseDir").(string)
	allowOverwrite := ctx.Value("allowOverwrite").(bool)
	maxBytes := ctx.Value("maxFileBytes").(int64)

	var args createArgs
	if err := req.BindArguments(&args); err != nil {
		return mcp.NewToolResultErrorf("invalid arguments: %v", err), nil
	}
	if args.Path == "" {
		return mcp.NewToolResultError("'path' is required"), nil
	}
	if args.Makedirs == nil {
		b := true
		args.Makedirs = &b
	}
	abs, relClean, err := resolveInsideBase(base, args.Path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if *args.Makedirs {
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return mcp.NewToolResultErrorf("mkdirs failed: %v", err), nil
		}
	}

	if _, err := os.Stat(abs); err == nil {
		overwrite := args.Overwrite != nil && *args.Overwrite && allowOverwrite
		if !overwrite {
			return mcp.NewToolResultError("file exists and overwrite not allowed"), nil
		}
	}
	// size guard
	if maxBytes > 0 && int64(len(args.Content)) > maxBytes {
		return mcp.NewToolResultErrorf("content too large: %d bytes (limit %d)", len(args.Content), maxBytes), nil
	}
	if err := os.WriteFile(abs, []byte(args.Content), 0o644); err != nil {
		return mcp.NewToolResultErrorf("write failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: filepath.ToSlash(relClean), Action: "created", Bytes: len(args.Content)}, "created"), nil
}

func handleUpdate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	base := ctx.Value("baseDir").(string)
	maxBytes := ctx.Value("maxFileBytes").(int64)

	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	content, err := req.RequireString("content")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	create := req.GetBool("create", false)

	abs, relClean, err := resolveInsideBase(base, path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if _, statErr := os.Stat(abs); errors.Is(statErr, os.ErrNotExist) {
		if !create {
			return mcp.NewToolResultError("file does not exist; pass create=true to create it"), nil
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return mcp.NewToolResultErrorf("mkdirs failed: %v", err), nil
		}
	}
	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return mcp.NewToolResultErrorf("content too large: %d bytes (limit %d)", len(content), maxBytes), nil
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		return mcp.NewToolResultErrorf("write failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: filepath.ToSlash(relClean), Action: "updated", Bytes: len(content)}, "updated"), nil
}

func handleDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	base := ctx.Value("baseDir").(string)
	p, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	abs, relClean, err := resolveInsideBase(base, p)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	st, err := os.Stat(abs)
	if err != nil {
		return mcp.NewToolResultErrorf("stat failed: %v", err), nil
	}
	if st.IsDir() {
		return mcp.NewToolResultError("refusing to delete a directory"), nil
	}
	if err := os.Remove(abs); err != nil {
		return mcp.NewToolResultErrorf("delete failed: %v", err), nil
	}
	return mcp.NewToolResultStructured(fileResult{Path: filepath.ToSlash(relClean), Action: "deleted", Bytes: 0}, "deleted"), nil
}

func handleRead(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	base := ctx.Value("baseDir").(string)
	p, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	maxBytes := req.GetInt("maxBytes", 1<<20) // 1MB default
	abs, relClean, err := resolveInsideBase(base, p)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return mcp.NewToolResultErrorf("read failed: %v", err), nil
	}
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	payload := struct {
		Path    string `json:"path"`
		Bytes   int    `json:"bytes"`
		Preview string `json:"preview"`
	}{
		Path:    filepath.ToSlash(relClean),
		Bytes:   len(b),
		Preview: string(b),
	}
	return mcp.NewToolResultStructured(payload, fmt.Sprintf("read %d bytes from %s", len(b), payload.Path)), nil
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
	if !allowPrivate {
		if private, perr := hostIsPrivate(u.Hostname()); perr != nil {
			return mcp.NewToolResultErrorf("host resolution failed: %v", perr), nil
		} else if private {
			return mcp.NewToolResultError("request blocked to private/localhost address; set allowPrivate=true to override"), nil
		}
	}

	headersJSON := strings.TrimSpace(req.GetString("headers", ""))
	headers := map[string]string{}
	if headersJSON != "" {
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return mcp.NewToolResultErrorf("invalid headers JSON: %v", err), nil
		}
	}

	body := req.GetString("body", "")
	timeoutSec := req.GetInt("timeoutSec", 20)
	maxBytes := req.GetInt("maxBytes", 1<<20) // 1MB default
	follow := req.GetBool("followRedirects", true)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	client := &http.Client{}
	if !follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
	if err != nil {
		return mcp.NewToolResultErrorf("request build failed: %v", err), nil
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return mcp.NewToolResultErrorf("request failed: %v", err), nil
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, int64(maxBytes)+1)
	b, _ := io.ReadAll(lr)
	trunc := len(b) > maxBytes
	if trunc {
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

// Determine whether a host resolves only to private/loopback/link-local/etc IPs.
func hostIsPrivate(host string) (bool, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return false, err
	}
	if len(ips) == 0 {
		return false, fmt.Errorf("no A/AAAA records")
	}
	allPrivate := true
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			allPrivate = false
			break
		}
	}
	return allPrivate, nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// RFC1918 / Unique local
	if ip.To4() != nil {
		v4 := ip.To4()
		switch {
		case v4[0] == 10: // 10.0.0.0/8
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31: // 172.16.0.0/12
			return true
		case v4[0] == 192 && v4[1] == 168: // 192.168.0.0/16
			return true
		}
		return false
	}
	// IPv6 unique local fc00::/7
	return len(ip) == net.IPv6len && (ip[0]&0xFE) == 0xFC
}

// ---------- helpers ----------

// resolveInsideBase returns (absPath, relClean) ensuring the target is within base.
func resolveInsideBase(base, rel string) (string, string, error) {
	cleanRel := filepath.Clean(strings.TrimPrefix(rel, string(filepath.Separator)))
	abs := filepath.Join(base, cleanRel)
	abs = filepath.Clean(abs)
	// Ensure base is a prefix of abs (on the same volume)
	baseWithSep := ensureTrailingSep(base)
	if !strings.HasPrefix(ensureTrailingSep(abs), baseWithSep) {
		return "", "", fmt.Errorf("path escapes base directory")
	}
	return abs, cleanRel, nil
}

func ensureTrailingSep(p string) string {
	p = filepath.Clean(p)
	if !strings.HasSuffix(p, string(filepath.Separator)) {
		p += string(filepath.Separator)
	}
	return p
}

func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.BaseDir, "base", ".", "Base directory the server will expose")
	flag.BoolVar(&cfg.AllowOverwrite, "allow-overwrite", false, "Permit fs_create to overwrite existing files when overwrite=true")
	flag.Int64Var(&cfg.MaxFileBytes, "max-bytes", 5<<20, "Max bytes accepted for create/update (0 = unlimited)")
	flag.Parse()
	return cfg
}

func checkFatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// Utility to pretty-print JSON for debug (unused but handy during development)
func toJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
