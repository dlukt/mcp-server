# mcp-fileserver

A sandboxed MCP (Model Context Protocol) server that exposes file & directory
CRUD inside one base directory tree, plus a guarded HTTP request tool.

Filesystem containment is enforced by [`os.Root`](https://go.dev/pkg/os/#Root)
(Linux `openat2` `RESOLVE_BENEATH`): no operation — read, write, delete, rename,
mkdir — can escape the base directory, even through symlinks. Paths are relative
to the base; `..` traversal and absolute paths are rejected.

## Requirements

- Go **1.26+** (uses `os.Root`)

## Install

```bash
go install github.com/dlukt/mcp-server@latest
```

## Run

```bash
mcp-server --base /path/to/sandbox \
  --allow-overwrite=false \
  --max-bytes=104857600   # 100MB per file; 0 = unlimited
```

The server speaks MCP over stdio. `--version` prints the version.

## Tools

| Tool | Description |
|---|---|
| `fs_list` | List entries under a path (optional `recursive`, `pattern` glob, `maxEntries`). Directories are suffixed with `/`. Does not descend through symlinks. |
| `fs_read` | Read a file (optional `maxBytes`). |
| `fs_stat` | Stat a file/dir/symlink: size, mode, mtime, symlink target. |
| `fs_create` | Create a file (`overwrite`, `makedirs`). Overwrite requires `overwrite=true` **and** server `--allow-overwrite`. |
| `fs_update` | Replace file contents (`create=true` to create if missing). |
| `fs_delete` | Delete a file or symlink; directories need `recursive=true`. |
| `fs_mkdir` | Create a directory (`parents=true` = `mkdir -p`, tolerates existing). |
| `fs_rename` | Rename/move; fails if destination exists (`makedirs=true`). |
| `http_request` | HTTP(S) request with status, headers, truncated body preview. |

### `http_request` security

- Connections to loopback/private/CGNAT/link-local IPs are **blocked at dial
  time** — this covers redirects and DNS rebinding (every TCP connection is
  validated, not just the first URL). `allowPrivate=true` overrides.
- Environment proxies (`HTTP_PROXY` etc.) are ignored; requests always dial
  directly so the IP guard cannot be bypassed via a proxy.
- Only `http`/`https` schemes; redirects to other schemes are blocked.

## Use in LM Studio / Claude / any MCP client

```json
{
  "mcpServers": {
    "mcp-fileserver": {
      "command": "/home/{{user}}/go/bin/mcp-server",
      "args": [
        "--base",
        "/home/{{user}}/mcproot",
        "--allow-overwrite=true",
        "--max-bytes",
        "104857600"
      ],
      "env": {}
    }
  }
}
```

Replace `{{user}}` with your username, or provide a different path.

## Testing

End-to-end tests speak MCP JSON-RPC over stdio: `python3 mcp_e2e.py [binary]`
covers all tools, traversal/symlink escapes, and the HTTP private-IP guard.
