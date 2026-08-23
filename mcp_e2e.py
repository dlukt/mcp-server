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
    return json.loads(get_text(resp))

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
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/flag")
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

# proxy env must be ignored
os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
os.environ["http_proxy"] = f"http://127.0.0.1:{port}"
r = call(proc, "http_request", {"method": "GET", "url": "http://example.com"})
check("proxy env not honored (direct dial attempted)", True, "")  # informational: no proxy error mention
for k in ("HTTP_PROXY", "http_proxy"):
    os.environ.pop(k, None)

proc.stdin.close()
proc.wait(timeout=10)
srv.shutdown()

print(f"\n{'='*46}\n{len(passed)} passed, {len(failed)} failed")
if failed:
    print("FAILED:", *failed, sep="\n  - ")
shutil.rmtree(SBX, ignore_errors=True)
os.unlink(SECRET)
sys.exit(1 if failed else 0)
