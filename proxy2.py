#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP 代理网关 - 用于监控和过滤大模型与 MCP 服务器之间的流量
结合 check2.py 实现 MCP 流量监控和安全检查
"""

import json
import os
import uuid
import asyncio

import httpx
from fastapi import FastAPI, HTTPException, Request
from starlette.responses import JSONResponse, StreamingResponse

from dotenv import load_dotenv
import sys 

# 加载环境变量
load_dotenv("/root/CSY/MCP_proxy/.env")

# 添加项目路径到 sys.path 以便导入 check2
sys.path.append('/root/CSY/MCP_proxy')
try:
    from check2 import check_mcp_request, call_llm_for_check
except ImportError:
    print("Warning: check2.py not found or check_mcp_request not available. Security checks will be skipped.", file=__import__('sys').stderr)
    def check_mcp_request(req):
        return {"decision": "ALLOW", "reason": "Check module missing"}
    def call_llm_for_check(req):
        return {"decision": "ALLOW", "reason": "Check module missing"}


class AppLogger:
    def __init__(self, log_file="llm.log"):
        """Initialize the logger with a file that will be cleared on startup."""
        self.log_file = log_file
        # Clear the log file on startup
        with open(self.log_file, 'w') as f:
            f.write("")

    def log(self, message):
        """Log a message to both file and console."""

        # Log to file
        with open(self.log_file, 'a') as f:
            f.write(message + "\n")

        # Log to console
        print(message)


def to_bearer(token: str) -> str:
    token = (token or "").strip()
    if not token:
        return ""
    if token.lower().startswith("bearer "):
        return token
    return f"Bearer {token}"


# 上游 LLM API 地址与鉴权 token
load_dotenv("/root/CSY/MCP_proxy/.env")

LLM_API_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1/chat/completions")
LLM_AUTH_HEADER = to_bearer(
    os.getenv("DEEPSEEK_API_KEY", "")  # 如果有 API 密钥的话
)

app = FastAPI(title="MCP Security Gateway")
logger = AppLogger("/root/CSY/MCP_proxy/llm.log")

# 注册文件路径
REGISTER_PATH = "/root/CSY/MCP_proxy/regester.json"
DEFAULT_BLOCKED_TOOLS = {"protect_files", "recover_files"}


def load_blocked_tools() -> set[str]:
    blocked = set(DEFAULT_BLOCKED_TOOLS)
    try:
        with open(REGISTER_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        tools = data.get("tools", [])
        blocked.update(
            tool.get("name")
            for tool in tools
            if tool.get("status") == "Vulnerable" and tool.get("name")
        )
    except Exception as e:
        logger.log(f"读取 regester.json 失败，使用默认危险工具列表: {e}")
    return blocked


def extract_tool_name_from_tool_choice(tool_choice) -> str | None:
    if isinstance(tool_choice, dict):
        function = tool_choice.get("function")
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            return function["name"]
        if isinstance(tool_choice.get("name"), str):
            return tool_choice["name"]
    return None


def extract_tool_names_from_response(data: dict) -> list[str]:
    names = []
    for choice in data.get("choices", []):
        message = choice.get("message", {})
        for tool_call in message.get("tool_calls", []):
            function = tool_call.get("function", {})
            name = function.get("name")
            if isinstance(name, str) and name:
                names.append(name)
        function_call = message.get("function_call", {})
        if isinstance(function_call, dict) and isinstance(function_call.get("name"), str):
            names.append(function_call["name"])
    return names


def parse_sse_json_line(line: str) -> dict | None:
    if not line.startswith("data:"):
        return None
    data_str = line[5:].strip()
    if not data_str or data_str == "[DONE]":
        return None
    try:
        return json.loads(data_str)
    except json.JSONDecodeError:
        return None


def extract_tool_names_from_chunk(chunk: dict, state: dict[int, str]) -> list[str]:
    names = []
    for choice in chunk.get("choices", []):
        delta = choice.get("delta", {})
        for tool_call in delta.get("tool_calls", []):
            index = tool_call.get("index", 0)
            function = tool_call.get("function", {})
            if not isinstance(function, dict):
                continue
            if "name" in function and isinstance(function.get("name"), str):
                merged_name = state.get(index, "") + function["name"]
                state[index] = merged_name
            if state.get(index):
                names.append(state[index])
    return names


def is_blocked_name(called_name: str, blocked_name: str) -> bool:
    if called_name == blocked_name:
        return True
    if called_name.endswith(blocked_name):
        prefix = called_name[:-len(blocked_name)]
        if not prefix:
            return True
        if prefix.endswith(("_", ":", ".", "/", "-")):
            return True
        if "mcp" in prefix.lower():
            return True
    return False


def find_blocked_tool(tool_names: list[str], blocked_tools: set[str]) -> str | None:
    for called_name in tool_names:
        for blocked_name in blocked_tools:
            if is_blocked_name(called_name, blocked_name):
                return called_name
    return None


def build_block_payload(tool_name: str, request_id: str) -> dict:
    return {
        "error": {
            "code": "MCP_TOOL_BLOCKED",
            "type": "policy_violation",
            "message": "危险 MCP 工具调用已被代理层拒绝",
        },
        "alert": {
            "show": True,
            "title": "已拦截高风险操作",
            "content": f"模型尝试调用工具 {tool_name}，已被安全策略阻止。",
            "level": "warning",
        },
        "blocked": {
            "keyword": "use_mcp_tool",
            "tool_name": tool_name,
            "source": "proxy",
            "policy": "regester.json:status=Vulnerable",
        },
        "request_id": request_id,
    }


def log_blocked_request(request_data, reason: str):
    """记录被拦截的 MCP 请求到 mcp_call.log 文件"""
    import time
    
    log_entry = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
        "request_id": request_data.get("id"),
        "method": request_data.get("method", "tools/call"),
        "tool_name": request_data.get("params", {}).get("name", ""),
        "arguments": request_data.get("params", {}).get("arguments", {}),
        "allowed": False,  # 表示被拦截
        "reason": reason,
    }
    
    try:
        with open("/root/CSY/MCP_proxy/mcp_call.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.log(f"Failed to write to mcp_call.log: {e}")


MCP_UPSTREAM_URL = "http://10.50.3.225:1234/mcp"

# 每个 Cline session -> 上游 mcp-session-id 的映射
_mcp_sessions: dict[str, str] = {}


@app.post("/mcp")
async def mcp_proxy(request: Request):
    body_bytes = await request.body()
    try:
        body = json.loads(body_bytes)
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    method = body.get("method", "")
    request_id = str(uuid.uuid4())

    # 取 Cline 传来的 session id（如果有）
    cline_session = request.headers.get("mcp-session-id", "")

    # 构造转发 headers
    upstream_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    # 如果已有映射的上游 session，带上
    upstream_session = _mcp_sessions.get(cline_session, "")
    if upstream_session:
        upstream_headers["mcp-session-id"] = upstream_session

    # ── tools/call 安全检测 ──────────────────────────────────────────
    if method == "tools/call":
        tool_name = body.get("params", {}).get("name", "")
        arguments = body.get("params", {}).get("arguments", {})

        # 静态黑名单
        blocked_tools = load_blocked_tools()
        if find_blocked_tool([tool_name], blocked_tools):
            reason = "静态黑名单拦截 (regester.json:status=Vulnerable)"
            log_blocked_request(
                {"id": request_id, "method": "tools/call", "params": {"name": tool_name, "arguments": arguments}},
                reason
            )
            logger.log(f"[MCP] 静态黑名单拦截: {tool_name}")
            return JSONResponse({
                "jsonrpc": "2.0", "id": body.get("id"),
                "error": {"code": -32600, "message": f"BLOCKED: {reason}"}
            }, status_code=403)

        # LLM 意图检测
        check_result = call_llm_for_check(json.dumps({
            "tool": tool_name,
            "arguments": arguments
        }, ensure_ascii=False))

        if check_result.get("decision") == "BLOCK":
            reason = check_result.get("reason", "Unknown")
            log_blocked_request(
                {"id": request_id, "method": "tools/call", "params": {"name": tool_name, "arguments": arguments}},
                reason
            )
            logger.log(f"[MCP] LLM 意图分析拦截: {tool_name}, reason={reason}")
            return JSONResponse({
                "jsonrpc": "2.0", "id": body.get("id"),
                "error": {"code": -32600, "message": f"BLOCKED: {reason}"}
            }, status_code=403)

    # ── 透明转发 ────────────────────────────────────────────────────
    async with httpx.AsyncClient(timeout=60) as client:
        upstream_resp = await client.post(
            MCP_UPSTREAM_URL,
            content=body_bytes,
            headers=upstream_headers,
        )

    # initialize 响应：保存上游 session id，映射到 Cline session
    new_upstream_session = upstream_resp.headers.get("mcp-session-id", "")
    if method == "initialize" and new_upstream_session:
        # 用 request_id 作为本次 Cline 的 session id（回传给 Cline）
        _mcp_sessions[request_id] = new_upstream_session
        logger.log(f"[MCP] 建立 session 映射: cline={request_id} -> upstream={new_upstream_session}")

    # 构造回传 headers
    resp_headers = {"Content-Type": upstream_resp.headers.get("content-type", "application/json")}
    if method == "initialize" and new_upstream_session:
        resp_headers["mcp-session-id"] = request_id  # 返回给 Cline 的是我们的 id

    logger.log(f"[MCP] {method} -> {upstream_resp.status_code}")

    return StreamingResponse(
        iter([upstream_resp.content]),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    )


@app.post("/chat/completions")
async def proxy_request(request: Request):
    if not LLM_AUTH_HEADER:
        logger.log("LLM_API_KEY is not set, continuing without auth header")

    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8')
    logger.log(f"模型请求：{body_str}")
    body = await request.json()
    request_id = str(uuid.uuid4())
    blocked_tools = load_blocked_tools()

    tool_name_from_choice = extract_tool_name_from_tool_choice(body.get("tool_choice"))
    blocked_name = find_blocked_tool([tool_name_from_choice] if tool_name_from_choice else [], blocked_tools)
    if blocked_name:
        payload = build_block_payload(blocked_name, request_id)
        logger.log(f"拦截请求前危险工具调用: {blocked_name}, request_id={request_id}")
        log_blocked_request(
            {"id": request_id, "method": "tools/call", "params": {"name": blocked_name, "arguments": {}}},
            "静态黑名单拦截 (regester.json:status=Vulnerable)"
        )
        return JSONResponse(content=payload, status_code=403)

    logger.log("模型返回：\n")

    headers = {
        "Content-Type": "application/json",
        "Authorization": LLM_AUTH_HEADER,
    }

    # LLM OpenAI 兼容接口：stream=True 走 SSE，stream=False 走普通 JSON
    if body.get("stream", False):
        headers["Accept"] = "text/event-stream"

        async def event_stream():
            tool_name_state: dict[int, str] = {}
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    LLM_API_URL,
                    json=body,
                    headers=headers,
                ) as response:
                    if response.status_code >= 400:
                        error_text = await response.aread()
                        error_msg = error_text.decode("utf-8", errors="replace")
                        logger.log(error_msg)
                        yield error_msg
                        return

                    async for line in response.aiter_lines():
                        chunk = parse_sse_json_line(line)
                        if chunk is not None:
                            names = extract_tool_names_from_chunk(chunk, tool_name_state)
                            blocked_name = find_blocked_tool(names, blocked_tools)
                            
                            # 针对 MCP 工具调用进行安全检查
                            for tool_call in chunk.get("choices", [{}])[0].get("delta", {}).get("tool_calls", []):
                                function = tool_call.get("function", {})
                                if function and "name" in function and isinstance(function.get("name"), str):
                                    tool_name = function["name"]
                                    
                                    # 检查是否为 MCP 工具调用
                                    if "mcp" in tool_name.lower():  # 仅对 MCP 工具进行检测，如果需要对所有工具检测，可以移除此条件
                                        # 构建 MCP 请求对象
                                        mcp_request = {
                                            "jsonrpc": "2.0",
                                            "id": request_id,
                                            "method": "tools/call",
                                            "params": {
                                                "name": tool_name,
                                                "arguments": json.loads(function.get("arguments", "{}"))
                                            }
                                        }
                                        
                                        # 使用 check2.py 的 call_llm_for_check 函数进行实时检测
                                        check_result = call_llm_for_check(json.dumps({
                                            "tool": tool_name,
                                            "arguments": json.loads(function.get("arguments", "{}"))
                                        }, ensure_ascii=False))
                                        
                                        if check_result.get("decision") == "BLOCK":
                                            # 记录被拦截的 MCP 请求到 mcp_call.log
                                            log_blocked_request(mcp_request, check_result.get('reason', 'Unknown'))
                                            
                                            payload = build_block_payload(tool_name, request_id)
                                            logger.log(f"通过意图分析拦截MCP工具调用: {tool_name}, request_id={request_id}")
                                            yield f"event: mcp_tool_blocked\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                                            yield "data: [DONE]\n\n"
                                            return

                        logger.log(line)
                        yield f"{line}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    async with httpx.AsyncClient(timeout=None) as client:
        response = await client.post(
            LLM_API_URL,
            json=body,
            headers=headers,
        )

    logger.log(response.text)

    response_json = response.json()
    
    # 对非流式响应也进行 MCP 调用检测
    tool_names = extract_tool_names_from_response(response_json)
    for tool_name in tool_names:
        if "mcp" in tool_name.lower():  # 仅对 MCP 工具进行检测
            # 检查响应中的工具调用参数
            for choice in response_json.get("choices", []):
                message = choice.get("message", {})
                for tool_call in message.get("tool_calls", []):
                    function = tool_call.get("function", {})
                    if function.get("name") == tool_name:
                        # 构建 MCP 请求对象
                        mcp_request = {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": json.loads(function.get("arguments", "{}"))
                            }
                        }
                        
                        # 使用 check2.py 的 call_llm_for_check 函数进行实时检测
                        check_result = call_llm_for_check(json.dumps({
                            "tool": tool_name,
                            "arguments": json.loads(function.get("arguments", "{}"))
                        }, ensure_ascii=False))
                        
                        if check_result.get("decision") == "BLOCK":
                            # 记录被拦截的 MCP 请求到 mcp_call.log
                            log_blocked_request(mcp_request, check_result.get('reason', 'Unknown'))
                            
                            payload = build_block_payload(tool_name, request_id)
                            logger.log(f"通过意图分析拦截MCP工具调用: {tool_name}, request_id={request_id}")
                            return JSONResponse(content=payload, status_code=403)

    blocked_name = find_blocked_tool(tool_names, blocked_tools)
    if blocked_name:
        payload = build_block_payload(blocked_name, request_id)
        logger.log(f"拦截非流式危险工具调用: {blocked_name}, request_id={request_id}")
        log_blocked_request(
            {"id": request_id, "method": "tools/call", "params": {"name": blocked_name, "arguments": {}}},
            "静态黑名单拦截 (regester.json:status=Vulnerable)"
        )
        return JSONResponse(content=payload, status_code=403)

    return JSONResponse(
        content=response_json,
        status_code=response.status_code,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5001)