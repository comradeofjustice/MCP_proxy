# chat.py
import json
import sqlite3
from pathlib import Path

import requests

# 模型服务地址
API_URL = "http://localhost:9870/v1/chat/completions"

BASE_DIR = Path(__file__).resolve().parent
SQL_FILE = BASE_DIR / "regesiter.sql"
DB_FILE = BASE_DIR / "register.db"
JSON_FILE = BASE_DIR / "regester.json"

# 设置system prompt
SYSTEM_PROMPT = """你是一名资深的 MCP (Model Context Protocol) 安全审计专家。
你的任务是审计用户提供的 Python 代码，识别其中的 MCP 工具并分析安全风险。

### 任务要求：
1. **工具提取**：识别所有通过 MCP SDK 注册的工具（如 @server.call_tool）。
2. **风险审计**：重点检查以下维度：
   - **注入风险**：命令注入、SQL注入、提示词注入（Prompt Injection）。
   - **权限风险**：是否违反最小权限原则（如无限制的文件/网络访问）。
   - **数据安全**：是否泄露 API Key、用户隐私或未脱敏的日志。
   - **MCP 特有风险**：工具描述投毒（Poisoning）、间接提示词注入。

### 输出格式（严格 JSON）：
请仅输出一个 JSON 对象，结构如下：
{
  "audit_summary": {
    "file_name": "文件名",
    "total_tools": 0,
    "vulnerable_count": 0
  },
  "tools": [
    {
      "name": "工具名称",
      "description": "工具描述摘要",
      "status": "Secure | Vulnerable",
      "issues": [
        {
          "type": "风险类型",
          "severity": "High/Medium/Low",
          "evidence": "问题代码片段",
          "line": 123,
          "description": "简单描述漏洞及其危害",
          "fix": "修复建议"
        }
      ]
    }
  ]
}

如果没有发现问题，"issues" 数组请留空，"status" 标为 "Secure"。
现在请你审计一下代码你只需要返回json，其他不能有多余的废话：
"""


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        with open(SQL_FILE, "r", encoding="utf-8") as f:
            conn.executescript(f.read())


def extract_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


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


def save_result(file_name: str, assistant_text: str) -> tuple[int, dict]:
    audit_json = extract_json(assistant_text)
    summary = audit_json.get("audit_summary", {})

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute(
            """
            INSERT INTO mcp_audit_results (file_name, total_tools, vulnerable_count, raw_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                summary.get("file_name") or file_name,
                summary.get("total_tools"),
                summary.get("vulnerable_count"),
                json.dumps(audit_json, ensure_ascii=False),
            ),
        )
        conn.commit()

    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(audit_json, f, ensure_ascii=False, indent=2)

    return cur.lastrowid, audit_json


# 使用示例
if __name__ == "__main__":
    target_file = BASE_DIR / "MCP_Severs" / "fastmcp_data_protect_server.py"

    init_db()

    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
        q = f.read()

    answer = chat("请审计以下 Python 代码的 MCP 工具安全性：\n\n" + q)
    print("助手回复:", answer)

    row_id, _ = save_result(str(target_file), answer)
    print(f"已写入数据库: {DB_FILE} (id={row_id})")
    print(f"已写入JSON文件: {JSON_FILE}")
