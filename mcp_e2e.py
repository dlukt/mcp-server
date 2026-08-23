#!/usr/bin/env python3
"""End-to-end test for mcp-fileserver: speaks MCP JSON-RPC over stdio."""
import json, os, shutil, subprocess, sys, tempfile, http.server, threading

BIN = sys.argv[1] if len(sys.argv) > 1 else "/tmp/mcp-new"
SBX = tempfile.mkdtemp(prefix="mcpsbx-")

# A secret that must never be readable through the sandbox.
SECRET = "/tmp/mcp-secret-" + os.urandom(4).hex()
with open(SECRET, "w") as f:
    f.write("T0PSECRET-ROOT-FILE")

passed, failed = [], []

def send(proc, obj):
    proc.stdin.write(json.dumps(obj).encode() + b"\n")
    proc.stdin.flush()

def rline(proc):
    line = proc.stdout.readline()
    return json.loads(line)

def call(proc, name, args, _id=[0]):
    _id[0] += 1
    send(proc, {"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
                "params": {"name": name, "arguments": args}})
    return rline(proc)

def is_err(resp):
    r = resp.get("result", {})
    return r.get("isError") is True

def get_text(resp):
    c = resp["result"]["content"]
    for item in c:
        if item.get("type") == "text":
            return item["text"]
    return None

def get_json(resp):
    sc = resp["result"].get("structuredContent")
    if sc is not None:
        return sc
    t = get_text(resp)
    if t is None or not t.lstrip().startswith(("{", "[")):
        raise AssertionError("no structured payload: " + repr(t))
    return json.loads(t)

def check(name, cond, detail=""):
    if cond:
        passed.append(name)
        print(f"  ok   {name}")
    else:
        failed.append(name)
        print(f"  FAIL {name}  {detail}")

proc = subprocess.Popen(
    [BIN, "--base", SBX],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

# initialize
send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26",
                        "clientInfo": {"name": "test", "version": "0"},
                        "capabilities": {}}})
init = rline(proc)
check("initialize", init.get("result", {}).get("serverInfo", {}).get("name") == "mcp-fileserver", str(init)[:200])
send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

# tools/list
tools = call(proc, "x", {}) # placeholder, replace below
# proper tools/list:
send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
tl = rline(proc)
names = sorted(t["name"] for t in tl["result"]["tools"])
check("tools/list has all 9 tools",
      names == ["fs_create", "fs_delete", "fs_list", "fs_mkdir", "fs_read",
                "fs_rename", "fs_stat", "fs_update", "http_request"], str(names))

print("== fs_create / fs_read / fs_list ==")
r = call(proc, "fs_create", {"path": "hello.txt", "content": "hello world"})
check("create hello.txt", not is_err(r), get_text(r))
r = call(proc, "fs_read", {"path": "hello.txt"})
check("read hello.txt", not is_err(r) and get_json(r)["preview"] == "hello world", get_text(r))
r = call(proc, "fs_create", {"path": "hello.txt", "content": "x"})
check("create existing fails (no overwrite)", is_err(r), get_text(r))
r = call(proc, "fs_create", {"path": "hello.txt", "content": "x", "overwrite": True})
check("overwrite blocked without --allow-overwrite", is_err(r), get_text(r))
r = call(proc, "fs_create", {"path": "sub/deep/dir/a.md", "content": "# A"})
check("create with nested makedirs", not is_err(r), get_text(r))
r = call(proc, "fs_list", {"path": "."})
j = get_json(r)
check("list root", not is_err(r) and "hello.txt" in j["paths"] and "sub/" in j["paths"], get_text(r))
r = call(proc, "fs_list", {"recursive": True})
j = get_json(r)
check("list recursive", "sub/deep/dir/a.md" in j["paths"], get_text(r))
r = call(proc, "fs_list", {"pattern": "*.md", "recursive": True})
j = get_json(r)
check("list pattern *.md", j["paths"] == ["sub/deep/dir/a.md"], get_text(r))

print("== fs_stat / fs_mkdir / fs_rename ==")
r = call(proc, "fs_stat", {"path": "sub"})
j = get_json(r)
check("stat dir", not is_err(r) and j["isDir"] is True, get_text(r))
r = call(proc, "fs_mkdir", {"path": "empty"})
check("mkdir", not is_err(r), get_text(r))
r = call(proc, "fs_mkdir", {"path": "empty", "parents": False})
check("mkdir existing fails (parents=false)", is_err(r), get_text(r))
r = call(proc, "fs_mkdir", {"path": "empty"})
check("mkdir -p on existing is no-op", not is_err(r), get_text(r))
r = call(proc, "fs_mkdir", {"path": "a/b/c", "parents": True})
check("mkdir -p", not is_err(r), get_text(r))
r = call(proc, "fs_rename", {"from": "hello.txt", "to": "renamed.txt"})
check("rename file", not is_err(r), get_text(r))
r = call(proc, "fs_rename", {"from": "renamed.txt", "to": "sub/inner.txt"})
check("rename into subdir", not is_err(r), get_text(r))
r = call(proc, "fs_rename", {"from": "nope.txt", "to": "x.txt"})
check("rename missing fails", is_err(r), get_text(r))

print("== fs_update / fs_delete ==")
r = call(proc, "fs_update", {"path": "sub/inner.txt", "content": "v2"})
check("update", not is_err(r), get_text(r))
r = call(proc, "fs_read", {"path": "sub/inner.txt"})
check("update persisted", get_json(r)["preview"] == "v2", get_text(r))
r = call(proc, "fs_update", {"path": "ghost.txt", "content": "x"})
check("update missing fails (no create)", is_err(r), get_text(r))
r = call(proc, "fs_delete", {"path": "sub"})
check("delete dir without recursive fails", is_err(r), get_text(r))
r = call(proc, "fs_delete", {"path": "sub", "recursive": True})
check("delete dir recursive", not is_err(r), get_text(r))
r = call(proc, "fs_list", {})
check("sub gone", "sub/" not in get_json(r)["paths"], get_text(r))

print("== security: traversal ==")
for bad in ["../secrets", "/etc/passwd", "a/../../..", "../" + os.path.basename(SECRET)]:
    r = call(proc, "fs_read", {"path": bad})
    check(f"read {bad!r} blocked", is_err(r), get_text(r))
r = call(proc, "fs_create", {"path": "../evil.txt", "content": "x"})
check("create ../evil.txt blocked", is_err(r), get_text(r))

print("== security: symlink escape ==")
os.symlink(SECRET, os.path.join(SBX, "leak"))
r = call(proc, "fs_read", {"path": "leak"})
check("read symlink to outside blocked by os.Root", is_err(r) and "T0PSECRET" not in get_text(r), get_text(r))
r = call(proc, "fs_list", {})
check("symlink listed but not followed", "leak" in get_json(r)["paths"], get_text(r))
r = call(proc, "fs_stat", {"path": "leak"})
check("stat symlink shows target", get_json(r).get("isSymlink") is True, get_text(r))
os.symlink("/etc", os.path.join(SBX, "etcdir"))
r = call(proc, "fs_list", {"path": "etcdir"})
check("listing through dir-symlink blocked", is_err(r), get_text(r))

print("== http_request ==")
# local server = private IP, must be blocked without allowPrivate
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path == "/loop":
            body = b"looping"
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/flag")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b"LOCAL-SERVER-BODY"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    def log_message(self, *a): pass

srv = http.server.HTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

r = call(proc, "http_request", {"method": "GET", "url": f"http://127.0.0.1:{port}/flag"})
check("direct private IP blocked", is_err(r), get_text(r))
r = call(proc, "http_request", {"method": "GET", "url": f"http://127.0.0.1:{port}/flag", "allowPrivate": True})
check("allowPrivate=true works", not is_err(r) and get_json(r)["statusCode"] == 200
      and get_json(r)["bodyPreview"] == "LOCAL-SERVER-BODY", get_text(r))

# redirect-to-localhost from a "public" URL: simulate via headers? We can't get a
# public URL to redirect to localhost here, so test that redirects are followed
# (dial-guard still applies on every hop).
r = call(proc, "http_request", {"method": "GET", "url": f"http://127.0.0.1:{port}/redirect", "allowPrivate": True})
check("redirects followed", get_json(r)["statusCode"] == 200, get_text(r))

r = call(proc, "http_request", {"method": "GET", "url": "ftp://example.com"})
check("non-http scheme blocked", is_err(r), get_text(r))
r = call(proc, "http_request", {"method": "GET", "url": f"http://127.0.0.1:{port}/flag", "allowPrivate": True, "maxBytes": 5})
j = get_json(r)
check("maxBytes truncation", j["truncated"] is True and j["bytes"] == 5, get_text(r))

# codex P2: redirect loop must stop at 10 hops
r = call(proc, "http_request", {"method": "GET", "url": f"http://127.0.0.1:{port}/loop", "allowPrivate": True})
txt = get_text(r) or ""
check("redirect loop stops (10-hop cap)", is_err(r) and "10 redirects" in txt, txt[:120])

# codex P1: whitespace-prefixed filename must not be redirected to the trimmed name
r = call(proc, "fs_create", {"path": " padded.txt", "content": "P"})
check("create ' padded.txt' (leading space)", not is_err(r), get_text(r))
r = call(proc, "fs_create", {"path": "padded.txt", "content": "T"})
check("create 'padded.txt' (no space)", not is_err(r), get_text(r))
r = call(proc, "fs_read", {"path": " padded.txt"})
check("' padded.txt' has its own content", get_json(r)["preview"] == "P", get_text(r))
r = call(proc, "fs_delete", {"path": "padded.txt"})
check("delete 'padded.txt' only", not is_err(r), get_text(r))
r = call(proc, "fs_read", {"path": " padded.txt"})
check("' padded.txt' survives delete of 'padded.txt'", get_json(r)["preview"] == "P", get_text(r))
r = call(proc, "fs_delete", {"path": " padded.txt"})
check("delete ' padded.txt' works", not is_err(r), get_text(r))

# codex R2 P1: absolute paths must be rejected outright, not silently rebased
r = call(proc, "fs_read", {"path": "/etc/passwd"})
check("absolute path /etc/passwd rejected", is_err(r) and "absolute" in (get_text(r) or "").lower(), get_text(r))
r = call(proc, "fs_create", {"path": "/abs.txt", "content": "A"})
check("absolute create /abs.txt rejected", is_err(r), get_text(r))
r = call(proc, "fs_list", {})
check("no abs.txt leaked into sandbox root", "abs.txt" not in get_json(r)["paths"], get_text(r))
import os as _os
check("no /abs.txt on host", not _os.path.exists("/abs.txt"))
r = call(proc, "fs_read", {"path": "~/x"})
check("~/x rejected as home-relative", is_err(r), get_text(r))

# codex R2 P2: rename must not clobber a concurrently created destination.
# Use the pre-check path (destination exists) to verify fs.ErrExist mapping;
# the atomicity itself is renameat2(RENAME_NOREPLACE) on Linux.
r = call(proc, "fs_create", {"path": "victim.txt", "content": "VICTIM"})
check("create victim.txt", not is_err(r), get_text(r))
r = call(proc, "fs_create", {"path": "src.txt", "content": "SRC"})
check("create src.txt", not is_err(r), get_text(r))
r = call(proc, "fs_rename", {"from": "src.txt", "to": "victim.txt"})
check("rename onto existing dest fails", is_err(r) and "exists" in (get_text(r) or "").lower(), get_text(r))
r = call(proc, "fs_read", {"path": "victim.txt"})
check("existing dest content intact after refused rename", get_json(r)["preview"] == "VICTIM", get_text(r))
r = call(proc, "fs_rename", {"from": "src.txt", "to": "sub2/moved.txt", "makedirs": True})
check("rename with makedirs works", not is_err(r), get_text(r))
r = call(proc, "fs_read", {"path": "sub2/moved.txt"})
check("moved file readable", get_json(r)["preview"] == "SRC", get_text(r))

# codex R6 P2: maxEntries boundary must not cry truncated at the exact boundary
for p in ("m01.txt", "m02.txt", "m03.txt"):
    r = call(proc, "fs_create", {"path": p, "content": "m"})
    assert not is_err(r), get_text(r)
r = call(proc, "fs_list", {"path": ".", "pattern": "m0*.txt", "maxEntries": 3})
j = get_json(r)
check("maxEntries exact boundary not truncated", j["truncated"] is False and j["count"] == 3, get_text(r))
r = call(proc, "fs_list", {"path": ".", "pattern": "m0*.txt", "maxEntries": 2})
j = get_json(r)
check("maxEntries below boundary truncated", j["truncated"] is True and j["count"] == 2, get_text(r))
r = call(proc, "fs_list", {"path": ".", "pattern": "m0*.txt", "maxEntries": 2, "recursive": True})
j = get_json(r)
check("sorted listing order", j["paths"] == sorted(j["paths"]), str(j["paths"]))

# codex P1: per-request transports must not accumulate idle keepalive sockets
def mcp_socket_fds(pid):
    import glob as _g
    n = 0
    for fd in _g.glob(f"/proc/{pid}/fd/*"):
        try:
            if os.path.islink(fd) and os.readlink(fd).startswith("socket:"):
                n += 1
        except OSError:
            pass
    return n

before = mcp_socket_fds(proc.pid)
for _ in range(6):
    r = call(proc, "http_request", {"method": "GET", "url": f"http://127.0.0.1:{port}/flag", "allowPrivate": True})
    assert not is_err(r), get_text(r)
after = mcp_socket_fds(proc.pid)
check("no idle-socket accumulation (CloseIdleConnections)", after <= before + 1, f"sockets before={before} after={after}")

# codex R7 P2: proxy env must be ignored — spawn a dedicated server WITH
# proxy vars set in its environment (os.environ changes here would not reach
# the already-running child). A proxy-honoring client would send the request
# for example.com to our local listener; if that happens (or the proxy is
# contacted at all), this check fails. example.com resolves to a public IP,
# so a direct dial must succeed or fail without ever touching the listener.
proxy_hits = []
class ProxyProbeH(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        proxy_hits.append(self.path)
        b = b"PROXY-WAS-USED"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a): pass

psrv = http.server.HTTPServer(("127.0.0.1", 0), ProxyProbeH)
pport = psrv.server_address[1]
threading.Thread(target=psrv.serve_forever, daemon=True).start()

env = dict(os.environ)
env["HTTP_PROXY"] = f"http://127.0.0.1:{pport}"
env["http_proxy"] = f"http://127.0.0.1:{pport}"
env["HTTPS_PROXY"] = f"http://127.0.0.1:{pport}"
env["https_proxy"] = f"http://127.0.0.1:{pport}"
env["ALL_PROXY"] = f"http://127.0.0.1:{pport}"
proc2 = subprocess.Popen([BIN, "--base", tempfile.mkdtemp(prefix="mcpsbx2-")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=env)
proc2.stdin.write(json.dumps({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}).encode()+b"\n"); proc2.stdin.flush()
proc2.stdout.readline()
proc2.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'); proc2.stdin.flush()
# allowPrivate=true disables the dial guard, so a proxy-honoring client
# would now actually contact the 127.0.0.1 proxy; an env-ignoring client
# dials example.com directly and never touches the listener.
r = call(proc2, "http_request", {"method":"GET","url":"http://example.com/","allowPrivate":True})
t = get_text(r) or ""
proxy_used = any("PROXY-WAS-USED" in json.dumps(r) for _ in [0]) or bool(proxy_hits)
check("proxy env not honored (proxy never contacted)", not proxy_used, f"proxy_hits={proxy_hits} resp={t[:120]}")
proc2.stdin.close(); proc2.wait(timeout=10)
psrv.shutdown()

proc.stdin.close()
proc.wait(timeout=10)
srv.shutdown()

print(f"\n{'='*46}\n{len(passed)} passed, {len(failed)} failed")
if failed:
    print("FAILED:", *failed, sep="\n  - ")
shutil.rmtree(SBX, ignore_errors=True)
os.unlink(SECRET)
sys.exit(1 if failed else 0)
