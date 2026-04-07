# chat.py
import json
import sqlite3
from pathlib import Path
import os
import time
import re

import requests

# 模型服务地址
API_URL = "http://localhost:9870/v1/chat/completions"

BASE_DIR = Path(__file__).resolve().parent

# 日志文件路径
MCP_CALL_LOG_FILE = "/root/CSY/MCP_proxy/mcp_call.log"

# 设置system prompt
SYSTEM_PROMPT = """# Role
你是一名高级 MCP (Model Context Protocol) 安全网关守卫。你的核心职责是实时分析流经网关的 MCP 工具调用请求（Tool Calls），识别并拦截潜在的安全威胁，保护后端服务器文件系统、数据隐私及系统稳定性。

# Context
- 用户通过 LLM 客户端发起 MCP 工具调用。
- 这些请求经过你（安全网关）进行实时审查。
- 你需要根据预定义的安全策略，决定是 `ALLOW`（放行）还是 `BLOCK`（拦截）该请求。
- 如果拦截，必须提供简短且明确的拒绝理由。

# Security Policies (Strict Enforcement)

## 1. 文件系统访问控制 (File System Access Control)
- **敏感目录禁止访问**: 严禁访问以下目录及其子目录：
  - `/root`, `/home`, `/etc`, `/var`, `/usr`, `/bin`, `/sbin`, `/boot`, `/proc`, `/sys`
  - 任何包含 `.ssh`, `.git`, `.env`, `credentials`, `secrets`, `passwords` 的路径。
- **工作目录限制**: 
  - 允许访问的工作目录通常为 `/root/CSY` 或其明确指定的子项目目录（如 `/root/CSY/MCP_proxy`）。
  - **路径遍历攻击检测**: 严格检测 `../` 序列。如果解析后的绝对路径超出了允许的工作目录范围，立即拦截。
  - **示例**: 如果允许 `/root/CSY`，则 `/root/CSY/../etc/passwd` 必须被拦截。

## 2. 危险操作拦截 (Dangerous Operations)
- **禁止删除操作**: 拦截任何可能删除文件、目录或数据的工具调用。
  - 关键词检测: `delete`, `remove`, `unlink`, `rm`, `drop`, `destroy`。
  - 即使是在允许目录下的删除操作，除非有显式的"高危操作确认"标记（当前场景默认无此标记），否则一律拦截。
- **禁止执行系统命令**: 
  - 拦截所有试图执行 Shell 命令的工具（如 `execute_command`, `run_script`），除非命令是只读的且非破坏性的（如 `ls`, `cat` 仅限非敏感文件）。
  - 严禁执行 `rm`, `chmod`, `chown`, `sudo`, `wget`, `curl` (指向外部不可信源), `pip install`, `npm install` 等。
- **禁止写入敏感配置**: 禁止修改系统级配置文件或环境变量文件。

## 3. MCP 特定安全防护
- **工具注入防御**: 检测工具参数中是否包含恶意的 JSON 注入或代码片段。
- **资源耗尽防护**: 如果检测到请求涉及递归深度过大、文件数量极大（如 `list_files` 递归根目录）或大文件读取，视为 DoS 攻击尝试，予以拦截。
- **权限提升检测**: 检测是否尝试调用未授权的管理员级 MCP 工具。

# Analysis Steps
对于每一个传入的 MCP 请求，请执行以下步骤：

1. **解析请求**: 提取 `tool_name` (工具名) 和 `arguments` (参数)。
2. **意图分类**: 判断该操作是 读取(Read)、写入(Write)、执行(Execute) 还是 删除(Delete)。
3. **路径规范化与校验**:
   - 将相对路径转换为绝对路径。
   - 检查是否存在 `../` 路径遍历。
   - 验证最终路径是否在 `ALLOWED_PATHS` 列表中。
4. **危险模式匹配**: 检查参数中是否包含敏感关键词或危险命令。
5. **决策**: 
   - 如果违反任何安全策略 -> `BLOCK`
   - 如果完全合规 -> `ALLOW`

# Allowed Paths (Whitelist)
- `/root/CSY` (及其子目录，但需排除敏感子文件夹如 `.git`)
- `/tmp` (仅限临时文件读写，禁止执行)

# Output Format
你必须仅输出一个 JSON 对象，不要包含任何其他文本或解释。

**格式 A: 允许 (Allow)**
{
  "decision": "ALLOW",
  "reason": "Request is safe and within allowed paths."
}

**格式 B: 拦截 (Block)**
{
  "decision": "BLOCK",
  "reason": "简短的拦截理由，例如：Attempted path traversal to /etc; Deletion operation not permitted; Access to sensitive directory /root denied."
}

# Few-Shot Examples

## Example 1: Safe Read
Input: {"tool": "read_file", "arguments": {"path": "/root/CSY/MCP_proxy/proxy.py"}}
Output: {"decision": "ALLOW", "reason": "Read operation within allowed directory."}

## Example 2: Path Traversal Attack
Input: {"tool": "read_file", "arguments": {"path": "/root/CSY/MCP_proxy/../../../etc/passwd"}}
Output: {"decision": "BLOCK", "reason": "Detected path traversal attempt targeting sensitive system file."}

## Example 3: Deletion Attempt
Input: {"tool": "delete_file", "arguments": {"path": "/root/CSY/temp/old_data.txt"}}
Output: {"decision": "BLOCK", "reason": "Deletion operations are strictly prohibited by security policy."}

## Example 4: Dangerous Command Execution
Input: {"tool": "execute_command", "arguments": {"command": "rm -rf /root/CSY/MCP_proxy/temp"}}
Output: {"decision": "BLOCK", "reason": "Execution of destructive shell command 'rm' is forbidden."}

## Example 5: Sensitive Directory Access
Input: {"tool": "list_files", "arguments": {"path": "/root/.ssh"}}
Output: {"decision": "BLOCK", "reason": "Access to sensitive directory .ssh is denied."}

# Current Request
{{request_json}}
输出格式严格保持中文
"""


def chat(question):
    """发送消息并获取回复"""
    response = requests.post(
        API_URL,
        json={
           
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": question}
            ],
            "max_tokens": 5000
        },
        timeout=60
    )

    try:
        data = response.json()
    except ValueError:
        raise RuntimeError(f"接口返回非 JSON: HTTP {response.status_code}, body={response.text[:500]}")

    if response.status_code != 200:
        raise RuntimeError(f"接口错误: HTTP {response.status_code}, body={data}")

    if "choices" not in data:
        raise RuntimeError(f"返回中缺少 choices，实际返回: {data}")

    return data["choices"][0]["message"]["content"]


def call_llm_for_check(request_json_str):
    """
    调用语言模型进行安全检查
    """
    try:
        # 准备请求到LLM
        question = f"请分析以下MCP请求的安全性：{request_json_str}"
        llm_output = chat(question)
        
        # 解析LLM返回的JSON
        # 提取JSON部分（以防LLM输出包含其他文本，如markdown代码块标记）
        # 尝试寻找最外层的花括号匹配
        json_match = re.search(r'\{.*\}', llm_output, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            decision_result = json.loads(json_str)
            
            # 验证返回结果包含必要的字段
            if "decision" not in decision_result:
                 return {
                    "decision": "BLOCK",
                    "reason": "LLM response missing 'decision' field"
                }
                
            return decision_result
        else:
            # 如果无法解析JSON，返回默认拦截
            return {
                "decision": "BLOCK",
                "reason": f"LLM output parsing failed: {llm_output}"
            }
    except Exception as e:
        # 如果LLM调用失败，出于安全考虑默认拦截
        return {
            "decision": "BLOCK",
            "reason": f"Security check failed due to error: {str(e)}"
        }


def check_mcp_request(request_data):
    """
    检查 MCP 请求是否安全
    :param request_data: MCP JSON-RPC 请求对象
    :return: {"decision": "ALLOW"|"BLOCK", "reason": str}
    """
    method = request_data.get("method", "")
    
    # 只对工具调用进行详细检查，其他请求（如 initialize, listTools）默认允许
    if method != "tools/call":
        return {"decision": "ALLOW", "reason": f"Pass-through for non-tool method: {method}"}

    tool_name = request_data.get("params", {}).get("name", "")
    arguments = request_data.get("params", {}).get("arguments", {})

    # 执行基础规则检查
    basic_check_result = perform_basic_checks(tool_name, arguments)
    if basic_check_result["decision"] == "BLOCK":
        log_mcp_call(request_data, False, basic_check_result["reason"])
        return basic_check_result

    # 如果基础检查通过，调用LLM进行深入分析
    request_json_str = json.dumps({
        "tool": tool_name,
        "arguments": arguments
    }, ensure_ascii=False)
    
    llm_result = call_llm_for_check(request_json_str)
    
    # 记录到日志
    is_allowed = llm_result["decision"] == "ALLOW"
    log_mcp_call(request_data, is_allowed, llm_result["reason"])
    
    return llm_result


def perform_basic_checks(tool_name, arguments):
    """
    执行基本安全检查
    """
    # 检查是否在硬编码的黑名单中
    if tool_name in DEFAULT_BLOCKED_TOOLS:
        return {
            "decision": "BLOCK",
            "reason": f"Tool '{tool_name}' is blacklisted by security policy"
        }

    # 检查参数中是否包含危险关键词
    args_str = json.dumps(arguments, ensure_ascii=False).lower()
    dangerous_keywords = [
        "rm ", "rm -", "delete", "remove", "unlink", "drop table", 
        "exec(", "eval(", "import os", "import subprocess", "chmod", 
        "chown", "sudo", "wget", "curl", "mv "
    ]
    
    for keyword in dangerous_keywords:
        if keyword in args_str:
            return {
                "decision": "BLOCK",
                "reason": f"Found dangerous keyword '{keyword}' in arguments"
            }

    # 检查路径安全性（如果有路径参数）
    path_params = extract_path_params(arguments)
    for path_str in path_params:
        path = Path(path_str)
        
        # 规范化路径
        try:
            normalized_path = Path(path_str).resolve()
        except:
            return {
                "decision": "BLOCK",
                "reason": f"Could not normalize path: {path_str}"
            }
            
        # 检查敏感目录访问
        sensitive_dirs = ['/root', '/home', '/etc', '/var', '/usr', '/bin', '/sbin', '/boot', '/proc', '/sys']
        for sensitive_dir in sensitive_dirs:
            if str(normalized_path).startswith(sensitive_dir):
                return {
                    "decision": "BLOCK",
                    "reason": f"Attempted access to sensitive directory: {normalized_path}"
                }
                
        # 检查隐藏文件或敏感目录
        path_parts = str(normalized_path).split('/')
        if '.ssh' in path_parts or '.git' in path_parts or '.env' in path_parts:
            return {
                "decision": "BLOCK",
                "reason": f"Attempted access to sensitive directory/file: {normalized_path}"
            }

    # 通过基本检查
    return {
        "decision": "ALLOW",
        "reason": "Passed basic security checks"
    }


def extract_path_params(args):
    """
    从参数中提取所有可能的路径参数
    """
    paths = []
    for key, value in args.items():
        if isinstance(value, str):
            # 检查是否看起来像路径
            if '/' in value or value.startswith('.') or value.startswith('~'):
                paths.append(value)
    return paths


DEFAULT_BLOCKED_TOOLS = {"protect_files", "recover_files"}


def log_mcp_call(request_data, allowed, reason):
    """
    记录 MCP 调用到日志文件
    """
    log_entry = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
        "request_id": request_data.get("id"),
        "method": request_data.get("method"),
        "tool_name": request_data.get("params", {}).get("name", ""),
        "arguments": request_data.get("params", {}).get("arguments", {}),
        "allowed": allowed,
        "reason": reason,
    }
    
    try:
        with open(MCP_CALL_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"Failed to write to log file: {e}")

if __name__ == "__main__":
    # 测试示例
    test_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/root/CSY/MCP_proxy/test.txt"
            }
        }
    }
    
    result = call_llm_for_check(test_request)
    print(json.dumps(result, indent=2, ensure_ascii=False))