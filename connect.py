import httpx
import json

# 配置参数
PROXY_URL = "http://127.0.0.1:5001/chat/completions"
# 如果你在环境变量里设置了 PROXY_AUTH_TOKEN，请填在这里；否则留空
PROXY_TOKEN = "" 

def chat_with_proxy(prompt, stream=True):
    headers = {
        "Content-Type": "application/json"
    }
    if PROXY_TOKEN:
        headers["Authorization"] = f"Bearer {PROXY_TOKEN}"

    payload = {
        "model": "deepseek-chat", # 这里的 model 取决于你的本地 LLM 服务
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": stream
    }

    print(f"--- 发送请求 (Stream={stream}) ---")
    
    try:
        with httpx.Client(timeout=None) as client:
            if stream:
                # 流式请求处理
                with client.stream("POST", PROXY_URL, json=payload, headers=headers) as r:
                    if r.status_code != 200:
                        print(f"错误: {r.read().decode()}")
                        return
                    
                    print("代理返回: ", end="", flush=True)
                    for line in r.iter_lines():
                        if line:
                            content = parse_sse_line(line)
                            if content is None:  # 表示 [DONE]
                                break
                            elif content:
                                print(content, end="", flush=True)
                    print()  # 换行
            else:
                # 普通请求处理
                response = client.post(PROXY_URL, json=payload, headers=headers)
                if response.status_code == 200:
                    print("代理返回:", response.json()['choices'][0]['message']['content'])
                else:
                    print(f"错误: {response.status_code} - {response.text}")
                    
    except Exception as e:
        print(f"连接代理失败: {e}")

def parse_sse_line(line: str):
    """解析SSE行，提取内容"""
    if line.startswith("data: "):
        data = line[6:]  # 移除 "data: " 前缀
        if data.strip() == "[DONE]":
            return None
        try:
            parsed = json.loads(data)
            if "choices" in parsed and len(parsed["choices"]) > 0:
                delta = parsed["choices"][0].get("delta", {})
                content = delta.get("content", "")
                return content
        except json.JSONDecodeError:
            pass
    return ""

if __name__ == "__main__":
    user_input = input("请输入你想问的问题: ")
    # 建议先用 stream=False 观察完整 JSON，再用 stream=True 测试性能
    chat_with_proxy(user_input, stream=True)