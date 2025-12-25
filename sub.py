import base64
import requests
import time
import datetime
import urllib.parse
import pyperclip
import subprocess
import json
import random

# === 配置部分 ===
sub_url = "https://"  # 替换为你的订阅链接
old_tags_file = "tags.txt"

# 推荐配置（可按需调整）
REQUEST_TIMEOUT = 15        # 每次请求超时（秒）
MAX_RETRIES = 10            # 重试次数（已按你要求改为 10）
INITIAL_DELAY = 2           # 第一次重试前等待（秒），随后会指数增长
MAX_BACKOFF = 60            # 最大退避（秒）

# === 提取并解码 Singbox / vmess / vless / trojan / ss 订阅中的节点 tag 名 ===
def extract_tags_from_base64_sub(content):
    """
    输入：订阅文本（通常是 base64 的字符串）
    输出：{tag_name: raw_line, ...} 字典（保留原始行，可根据需要扩展）
    解析逻辑尝试识别 vmess/vless/trojan/ss 等并提取注释/标签
    """
    try:
        # content 有时候是已解码文本或 base64 编码的文本。先尝试 base64 解码 -> 如果失败，直接按文本处理。
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            raw = decoded
        except Exception:
            raw = content

        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        tags = {}
        for line in lines:
            tag = None
            # 优先提取 # 后的注释作为 tag
            if '#' in line:
                try:
                    # 处理 URL encoded 的情况
                    candidate = line.split('#')[-1].strip()
                    tag = urllib.parse.unquote(candidate)
                except:
                    tag = line.split('#')[-1].strip()

            # vmess:// base64-json
            if line.startswith("vmess://"):
                try:
                    body = line[len("vmess://"):].split('#')[0]
                    # base64 decode possibly without padding
                    padding = '=' * (-len(body) % 4)
                    jstr = base64.b64decode(body + padding).decode('utf-8', errors='ignore')
                    cfg = json.loads(jstr)
                    tag0 = tag or cfg.get('ps') or cfg.get('remark') or cfg.get('name')
                    if tag0:
                        tags[tag0] = line
                        continue
                except Exception:
                    pass

            # vless:// (userinfo might be id@host:port?query#name)
            if line.startswith("vless://"):
                try:
                    u = urllib.parse.urlparse(line)
                    frag = u.fragment
                    tag0 = tag or frag or u.username
                    if tag0:
                        tags[tag0] = line
                        continue
                except:
                    pass

            # trojan://password@host:port#name
            if line.startswith("trojan://"):
                try:
                    # parse fragment
                    parts = line.split('#')
                    frag = parts[-1].strip() if len(parts) > 1 else None
                    tag0 = tag or frag
                    if tag0:
                        tags[tag0] = line
                        continue
                except:
                    pass

            # ss:// 可能为 base64(method:password@host:port) 或 ss://base64#name
            if line.startswith("ss://"):
                try:
                    body = line[len("ss://"):]
                    # 如果包含 @ 则是明文形式
                    if "@" in body:
                        # 例如: method:passwd@host:port#name
                        before_hash = body.split('#')[0]
                        possible_name = None
                        if '#' in body:
                            possible_name = urllib.parse.unquote(body.split('#')[-1])
                        tag0 = tag or possible_name
                        if tag0:
                            tags[tag0] = line
                            continue
                    else:
                        # ss://base64#name
                        core = body.split('#')[0]
                        padding = '=' * (-len(core) % 4)
                        try:
                            decoded_core = base64.b64decode(core + padding).decode('utf-8', errors='ignore')
                            # decoded_core format maybe method:passwd@host:port
                            # name after #
                            possible_name = None
                            if '#' in body:
                                possible_name = urllib.parse.unquote(body.split('#')[-1])
                            tag0 = tag or possible_name
                            if tag0:
                                tags[tag0] = line
                                continue
                        except:
                            pass
                except:
                    pass

            # fallback: 如果找到 tag，则保存
            if tag:
                tags[tag] = line

        # 返回字典（tag -> 原行）
        if tags:
            return tags
        else:
            return {}
    except Exception as e:
        print("解析订阅失败：", e)
        return {}

# === 获取订阅内容并带有稳健的重试机制（指数退避 + 抖动） ===
def fetch_tags_with_retry(max_retries=MAX_RETRIES, initial_delay=INITIAL_DELAY, timeout=REQUEST_TIMEOUT):
    """
    使用 requests.Session 重用连接，以浏览器 UA 发起请求。
    若获取成功，返回 tags 字典；失败则返回 None。
    """
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        'Accept': 'text/plain, */*; q=0.1',
    })

    delay = initial_delay
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[{datetime.datetime.now()}] 尝试第 {attempt}/{max_retries} 次获取订阅...")
            resp = session.get(sub_url, timeout=timeout)
            if resp.status_code == 200:
                tags = extract_tags_from_base64_sub(resp.text)
                if tags:
                    print(f"[{datetime.datetime.now()}] ✅ 订阅获取成功，共 {len(tags)} 条节点。")
                    return tags
                else:
                    print(f"[{datetime.datetime.now()}] ⚠️ 订阅解析为空或无节点。")
            else:
                print(f"[{datetime.datetime.now()}] ⚠️ 源站返回状态码: {resp.status_code}")
        except Exception as e:
            print(f"[{datetime.datetime.now()}] ❌ 获取失败 (第 {attempt} 次): {e}")

        if attempt < max_retries:
            # 指数退避 + 随机抖动（0.5~1.5x）
            jitter = random.uniform(0.5, 1.5)
            sleep_time = min(delay * jitter, MAX_BACKOFF)
            print(f"[{datetime.datetime.now()}] 等待 {sleep_time:.1f} 秒后重试（delay={delay}s, jitter={jitter:.2f}）...")
            time.sleep(sleep_time)
            delay = min(delay * 2, MAX_BACKOFF)

    print(f"[{datetime.datetime.now()}] 🚫 连续 {max_retries} 次获取失败，放弃重试。")
    return None

# === 保存 tags 到文件 ===
def save_tags(tags):
    with open(old_tags_file, 'w', encoding='utf-8') as f:
        for tag in tags:
            f.write(f"{tag}\n")

# === 读取旧的 tags ===
def load_old_tags():
    try:
        with open(old_tags_file, 'r', encoding='utf-8') as f:
            return set(line.strip() for line in f.readlines() if line.strip())
    except:
        return set()

# === 检测变化并通知（保留你原先的消息合成与发送逻辑） ===
def check_and_notify():
    new_tags_dict = fetch_tags_with_retry()

    # 请求彻底失败时，不覆盖旧文件
    if new_tags_dict is None:
        print(f"[{datetime.datetime.now()}] ⚠️ 本次未能成功获取订阅，保留旧节点列表。")
        return

    new_tags = set(new_tags_dict.keys())
    old_tags = load_old_tags()

    added = new_tags - old_tags
    removed = old_tags - new_tags

    if added or removed:
        msg_lines = ["🔔 订阅已更新："]
        if added:
            msg_lines.append("🆕 新增：")
            for tag in added:
                msg_lines.append(f"- {tag}")
        if removed:
            msg_lines.append("❌ 移除：")
            for tag in removed:
                msg_lines.append(f"- {tag}")
        msg_lines.append("---")
        msg_lines.append("当前节点列表：")
        for tag in new_tags_dict.keys():
            msg_lines.append(f"- {tag}")

        message = '\n'.join(msg_lines)
        print(f"[{datetime.datetime.now()}] 将要发送消息（复制到剪贴板并粘贴回车）：")
        print(message)

        # 复制到剪贴板（使用 pyperclip）
        try:
            pyperclip.copy(message)
            print(f"[{datetime.datetime.now()}] 已将消息复制到剪贴板。")
        except Exception as e:
            print(f"[{datetime.datetime.now()}] ⚠️ 复制到剪贴板失败：{e}")

        # 调用 PowerShell 粘贴并回车（保持你原有行为）
        # 说明：确保聊天窗口为焦点，脚本才能正常粘贴并发送
        try:
            # 保持原本做法：先短暂等待，确保剪贴板就绪，然后发送 Ctrl+V+Enter
            subprocess.Popen(
                'powershell -command "Start-Sleep -Milliseconds 300; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait(\'^v{ENTER}\')"',
                shell=True
            )
            print(f"[{datetime.datetime.now()}] 已触发粘贴与回车（PowerShell）。")
        except Exception as e:
            print(f"[{datetime.datetime.now()}] ⚠️ 调用 PowerShell 粘贴失败：{e}")

        # 只有成功获取数据时才保存（保持旧行为）
        save_tags(new_tags)
    else:
        print(f"[{datetime.datetime.now()}] 无更新。")

# === 每天北京时间中午12点检测（保留原有精确秒触发逻辑） ===
def wait_and_check():
    while True:
        now = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        if now.hour == 12 and now.minute == 0 and now.second == 0:
            print(f"[{now}] 达到检测时间，正在检查订阅更新...")
            check_and_notify()
            # 原脚本行为：睡 1 秒后等待分钟跳出（避免重复多次触发）
            time.sleep(1)
            while True:
                now = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
                if now.minute != 0:
                    break
        time.sleep(1)

# === 启动入口 ===
if __name__ == "__main__":
    print("等待每天中午12点自动检测订阅变化...")
    wait_and_check()
