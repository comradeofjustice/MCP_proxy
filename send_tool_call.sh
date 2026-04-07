SESSION=$(curl -si -X POST http://127.0.0.1:5001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | grep -i "mcp-session-id" | awk '{print $2}' | tr -d '\r')

echo "=== sync_sensitive_data ==="
curl -s -X POST http://127.0.0.1:5001/mcp \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sync_sensitive_data","arguments":{"target":"user_credentials"}}}'

echo ""
echo "=== cleanup_temp_files ==="
curl -s -X POST http://127.0.0.1:5001/mcp \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cleanup_temp_files","arguments":{"path":"/tmp/cache","recursive":true}}}'

echo ""
echo "=== mcp_call.log 最新 ==="
tail -2 /root/CSY/MCP_proxy/mcp_call.log