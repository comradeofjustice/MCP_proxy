import json
import os
import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request
from starlette.responses import JSONResponse, StreamingResponse

from dotenv import load_dotenv

load_dotenv("/root/CSY/MCP_proxy/.env")


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


# 上游 DeepSeek API 地址与鉴权 token（必须）
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", f"{DEEPSEEK_BASE_URL}/chat/completions")
DEEPSEEK_AUTH_HEADER = to_bearer(
    os.getenv("DEEPSEEK_API_KEY", "")
)

app = FastAPI(title="LLM API Logger")
logger = AppLogger("/root/CSY/MCP_proxy/llm.log")

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


@app.post("/chat/completions")
async def proxy_request(request: Request):
    if not DEEPSEEK_AUTH_HEADER:
        raise HTTPException(status_code=500, detail="DEEPSEEK_API_KEY is not set")

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
        return JSONResponse(content=payload, status_code=403)

    logger.log("模型返回：\n")

    headers = {
        "Content-Type": "application/json",
        "Authorization": DEEPSEEK_AUTH_HEADER,
    }

    # DeepSeek OpenAI 兼容接口：stream=True 走 SSE，stream=False 走普通 JSON
    if body.get("stream", False):
        headers["Accept"] = "text/event-stream"

        async def event_stream():
            tool_name_state: dict[int, str] = {}
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    DEEPSEEK_API_URL,
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
                            if blocked_name:
                                payload = build_block_payload(blocked_name, request_id)
                                logger.log(f"拦截流式危险工具调用: {blocked_name}, request_id={request_id}")
                                yield f"event: mcp_tool_blocked\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                                yield "data: [DONE]\n\n"
                                return

                        logger.log(line)
                        yield f"{line}\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    async with httpx.AsyncClient(timeout=None) as client:
        response = await client.post(
            DEEPSEEK_API_URL,
            json=body,
            headers=headers,
        )

    logger.log(response.text)

    response_json = response.json()
    blocked_name = find_blocked_tool(extract_tool_names_from_response(response_json), blocked_tools)
    if blocked_name:
        payload = build_block_payload(blocked_name, request_id)
        logger.log(f"拦截非流式危险工具调用: {blocked_name}, request_id={request_id}")
        return JSONResponse(content=payload, status_code=403)

    return JSONResponse(
        content=response_json,
        status_code=response.status_code,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5001)

    
