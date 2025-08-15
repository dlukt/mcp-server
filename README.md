# MCP server

For file operations and doing HTTP requests.

## install

go install github.com/dlukt/mcp-server@latest

## run

```bash
./mcp-fileserver --base /path/to/sandbox \
  --allow-overwrite=false \
  --max-bytes=104857600 # 100MB
```

## use in LM Studio


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

Replace `{{user}}` with your username, or provide different a path.
