"""
============================================================================
 教育用途远程管理框架 - 配置文件
 Educational Remote Administration Framework - Configuration
============================================================================

 【法律声明 / LEGAL NOTICE】
 本项目仅供网络安全教育、授权渗透测试和防御研究使用。
 未经授权对他人系统使用本软件属于违法行为。
 使用者须自行承担所有法律责任。

 This project is for cybersecurity education, authorized penetration
 testing, and defensive research ONLY. Unauthorized use against systems
 you do not own or have explicit permission to test is ILLEGAL.
============================================================================

 学习要点：
   - C2 (Command & Control) 服务端配置
   - 客户端回连配置
   - 通信加密参数
   - 心跳间隔与超时
   - 持久化选项（用于理解恶意软件行为）
"""

import os
import sys
import hashlib
from dataclasses import dataclass, field
from typing import Optional


# ============================================================================
# 网络配置 / Network Configuration
# ============================================================================

@dataclass
class NetworkConfig:
    """C2 服务器网络配置"""

    # 服务端监听地址（0.0.0.0 = 所有网卡）
    # 实际攻击常使用 CDN/域前置隐藏真实 IP —— 学习如何检测这类流量
    server_host: str = "0.0.0.0"
    server_port: int = 8443  # 非标准端口，减少与常见服务的冲突

    # TLS/SSL 配置（生产级远控通常使用 TLS 伪装成 HTTPS 流量）
    # 教育用途：理解如何检测加密 C2 流量（JA3/JARM 指纹、证书透明度日志）
    use_tls: bool = False
    cert_file: str = "server.crt"
    key_file: str = "server.key"

    # 心跳间隔（秒）—— 防守方可通过异常心跳频率检测 C2 通信
    heartbeat_interval: int = 30

    # 连接超时（秒）
    connect_timeout: int = 10
    recv_timeout: int = 60


# ============================================================================
# 加密配置 / Encryption Configuration
# ============================================================================

@dataclass
class CryptoConfig:
    """
    加密配置
    攻击者常用 AES-GCM（对称加密）保护 C2 通信。
    防守方学习方法：网络层无法解密，但可通过流量元数据（包大小、
    时间间隔、熵值分析）来检测加密 C2 流量。
    """

    # AES 密钥长度：16 (AES-128), 24 (AES-192), 32 (AES-256)
    key_size: int = 32  # AES-256

    # GCM 模式 nonce 长度（固定 12 字节为最佳实践）
    nonce_size: int = 12

    # 预共享密钥（教育用途固定密钥）
    # 实际恶意软件常用：DGA 生成密钥、从 C2 协商密钥、硬编码
    # 防守方可通过内存取证提取硬编码密钥
    preshared_secret: str = "edu_rat_demo_key_2024_do_not_use_in_prod"

    @property
    def derived_key(self) -> bytes:
        """从预共享密钥派生 AES 密钥（使用 SHA-256 KDF）"""
        return hashlib.sha256(self.preshared_secret.encode()).digest()


# ============================================================================
# 客户端配置 / Client Configuration
# ============================================================================

@dataclass
class ClientConfig:
    """
    客户端（植入体）配置

    教育要点：
    - 持久化机制：了解攻击者如何维持访问
    - 进程注入：了解无文件攻击
    - 反沙箱：了解恶意软件如何检测分析环境
    """

    # 唯一客户端标识（实际中常通过 WMI/系统信息生成）
    client_id: str = field(default_factory=lambda: f"AGENT-{os.getpid()}")

    # 回连模式
    callback_host: str = "127.0.0.1"
    callback_port: int = 8443

    # 最大重连次数（-1 表示无限重连 —— 典型的恶意软件行为）
    max_reconnect_attempts: int = -1

    # 重连间隔基础值（秒），实际使用会加入随机抖动
    reconnect_base_delay: float = 5.0
    reconnect_max_delay: float = 300.0  # 最大退避

    # 持久化选项（教育用途：理解恶意软件持久化技术）
    enable_persistence: bool = False
    persistence_methods: list = field(default_factory=lambda: [
        "registry_run_key",    # HKCU\...\Run
        "scheduled_task",      # 计划任务
        "startup_folder",      # 启动文件夹
    ])

    # 反分析选项（教育用途：理解恶意软件如何对抗分析）
    # 注意：这是双刃剑，防御方需要了解这些技术才能检测
    anti_sandbox: bool = False
    anti_debug: bool = False

    # 静默模式（减少日志/痕迹）
    silent_mode: bool = True


# ============================================================================
# 日志配置 / Logging Configuration
# ============================================================================

@dataclass
class LogConfig:
    """日志配置 —— 用于审计和学习追踪"""

    # 日志级别
    level: str = "INFO"

    # 日志文件路径
    file_path: str = "edu_rat.log"

    # 是否记录命令执行历史（审计用途）
    log_commands: bool = True

    # 最大日志文件大小 (MB)
    max_file_size_mb: int = 10


# ============================================================================
# 全局配置实例 / Global Configuration Instance
# ============================================================================

@dataclass
class Config:
    """全局配置"""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    client: ClientConfig = field(default_factory=ClientConfig)
    log: LogConfig = field(default_factory=LogConfig)

    # 版本信息
    version: str = "1.0.0-educational"


# 单例配置
config = Config()
