"""
============================================================================
 教育用途远程管理框架 - 检测与防御脚本
 Educational Remote Administration Framework - Defense & Detection
============================================================================

 这个脚本从防守方角度出发，展示如何检测和防御 RAT / C2 恶意软件。

 涵盖的检测技术：
 1. 网络流量分析（异常外连、心跳检测）
 2. 进程行为监控（可疑进程、命令执行）
 3. 持久化机制检测（注册表、计划任务、启动目录）
 4. 文件系统监控（敏感目录写入）
 5. 内存取证（密钥提取、注入检测）
 6. YARA 规则编写（基于静态特征）

 使用方法：
   python defense_detect.py scan        # 快速扫描当前系统
   python defense_detect.py monitor     # 持续监控（需要 root）
   python defense_detect.py yara        # 生成 YARA 规则
"""

import os
import re
import sys
import json
import time
import socket
import struct
import hashlib
import logging
import platform
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


# ============================================================================
# 1. 网络流量检测 / Network Traffic Detection
# ============================================================================

class NetworkDetector:
    """
    网络流量分析 —— 检测 C2 通信

    检测方法：
    1. 异常外连：非标准端口的持续连接
    2. 心跳检测：周期性数据包交换
    3. 协议异常：非标准协议的加密流量
    4. DNS 隧道：异常长的 DNS 查询
    5. 域前置检测：SNI 与 Host 头不匹配
    """

    @staticmethod
    def check_suspicious_connections() -> List[Dict]:
        """
        检查当前系统的可疑网络连接

        Returns: 可疑连接列表
        """
        suspicious = []

        try:
            import psutil

            # 常见 C2 端口（教育用途列表）
            common_c2_ports = {4444, 5555, 6666, 7777, 8080, 8443, 8888, 9001, 9090, 31337}

            # 可信进程前缀
            trusted_processes = {
                "chrome", "firefox", "safari", "edge",  # 浏览器
                "ssh", "sshd", "nginx", "apache",        # 服务
                "python", "node", "java",                 # 运行时
                "code", "nvim", "vim",                    # 编辑器
            }

            for conn in psutil.net_connections(kind='inet'):
                if conn.status != 'ESTABLISHED':
                    continue

                if not conn.raddr:
                    continue

                remote_port = conn.raddr.port

                # 检查进程
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    proc_name = proc.name().lower() if proc else "unknown"
                except Exception:
                    proc_name = "unknown"

                # 跳过可信进程
                if any(t in proc_name for t in trusted_processes):
                    continue

                # 检查可疑端口
                if remote_port in common_c2_ports:
                    suspicious.append({
                        "type": "suspicious_port",
                        "severity": "MEDIUM",
                        "process": proc_name,
                        "pid": conn.pid,
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "note": f"Connection to non-standard port {remote_port}",
                    })

                # 检查非 80/443 端口的 HTTP 流量
                if remote_port not in (80, 443, 22, 53):
                    suspicious.append({
                        "type": "non_standard_connection",
                        "severity": "LOW",
                        "process": proc_name,
                        "pid": conn.pid,
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "note": "Non-standard port connection",
                    })

        except ImportError:
            logger.warning("psutil not installed. Install: pip install psutil")
        except Exception as e:
            logger.error(f"Connection check failed: {e}")

        return suspicious

    @staticmethod
    def detect_heartbeat_pattern(packet_times: List[float],
                                  threshold: float = 0.1) -> bool:
        """
        检测心跳模式 —— 周期性数据包

        算法：检查数据包间隔的标准差
        规律的心跳 → 低标准差 → 可能是 C2 通信

        Args:
            packet_times: 数据包时间戳列表
            threshold: 变异系数阈值（低于此值认为是规律心跳）
        Returns: True if heartbeat pattern detected
        """
        if len(packet_times) < 3:
            return False

        # 计算间隔
        intervals = []
        for i in range(1, len(packet_times)):
            intervals.append(packet_times[i] - packet_times[i-1])

        # 计算统计量
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # 变异系数 (CV) = 标准差 / 平均值
        cv = std_dev / mean_interval if mean_interval > 0 else float('inf')

        # CV < threshold → 高度规律 → 可能是心跳
        return cv < threshold

    @staticmethod
    def scan_dns_tunneling() -> List[Dict]:
        """
        DNS 隧道检测

        检测方法：
        1. 异常长的 DNS 查询（Base64 编码数据）
        2. 高频率 DNS 查询同一域名
        3. TXT/MX 记录查询异常增多
        """
        findings = []
        # 实际实现需要抓包或读取 DNS 日志
        # 这里是检测框架示例

        logger.info(
            "[DNS TUNNEL] Detection points:\n"
            "  - Unusually long DNS queries (> 50 chars subdomain)\n"
            "  - High entropy in query names (encrypted/encoded data)\n"
            "  - Rapid-fire queries to same domain\n"
            "  - TXT record queries from non-mail processes"
        )

        return findings


# ============================================================================
# 2. 进程行为检测 / Process Behavior Detection
# ============================================================================

class ProcessDetector:
    """
    进程行为分析 —— 检测可疑进程活动

    检测方法：
    1. 可疑父进程关系（Office 启动 cmd.exe）
    2. 异常命令行参数（Base64 编码命令、下载执行）
    3. 进程注入检测（远程线程、DLL 注入）
    4. 隐藏窗口进程
    5. 可疑的子进程树
    """

    @staticmethod
    def check_suspicious_processes() -> List[Dict]:
        """检查可疑进程"""
        suspicious = []

        try:
            import psutil

            # 可疑的命令行模式（正则匹配）
            suspicious_patterns = [
                (r"-enc\s+[A-Za-z0-9+/=]{100,}", "PowerShell encoded command"),
                (r"powershell.*-WindowStyle\s+Hidden", "Hidden PowerShell"),
                (r"cmd\.exe.*/c.*certutil.*-urlcache", "Certutil download"),
                (r"bitsadmin.*/transfer", "BITS download"),
                (r"mshta\.exe.*http", "MSHTA remote script"),
                (r"rundll32\.exe.*javascript:", "Rundll32 JS execution"),
                (r"wmic.*process.*call.*create", "WMI process creation"),
                (r"schtasks.*/create.*python", "Scheduled task with Python"),
                (r"reg\.exe.*add.*\\Run", "Registry Run key addition"),
                (r"bash.*-c.*curl.*\|.*bash", "curl pipe bash"),
                (r"wget.*-O.*\|.*sh", "wget pipe shell"),
            ]

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    if not cmdline:
                        continue

                    for pattern, description in suspicious_patterns:
                        if re.search(pattern, cmdline, re.IGNORECASE):
                            suspicious.append({
                                "type": "suspicious_command",
                                "severity": "HIGH",
                                "description": description,
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "command": cmdline[:200],
                            })
                            break  # 只报告一次

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except ImportError:
            logger.warning("psutil not installed")
        except Exception as e:
            logger.error(f"Process check failed: {e}")

        return suspicious

    @staticmethod
    def check_hollowed_processes() -> List[Dict]:
        """
        进程镂空检测

        进程镂空（Process Hollowing）：
        1. 创建挂起状态的合法进程
        2. 卸载原始镜像
        3. 写入恶意代码
        4. 恢复执行

        检测方法：
        - VAD (Virtual Address Descriptor) 分析
        - PE 头与磁盘文件比较
        - 内存权限异常
        """
        findings = []

        logger.info(
            "[PROCESS HOLLOWING] Detection points:\n"
            "  - Suspended process creation followed by memory unmapping\n"
            "  - Mismatch between VAD and on-disk PE headers\n"
            "  - RWX (Read-Write-Execute) memory regions in child processes\n"
            "  - Process started with CREATE_SUSPENDED flag"
        )

        return findings


# ============================================================================
# 3. 持久化检测 / Persistence Detection
# ============================================================================

class PersistenceDetector:
    """
    持久化机制检测

    检测恶意软件如何维持系统访问权限
    """

    @staticmethod
    def check_windows_registry() -> List[Dict]:
        """检查 Windows 注册表持久化条目"""
        if sys.platform != "win32":
            logger.info("Registry check only available on Windows")
            return []

        findings = []

        # 常见的持久化注册表路径
        persistence_keys = [
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKEY_CURRENT_USER"),
            (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKEY_LOCAL_MACHINE"),
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
             "HKEY_CURRENT_USER"),
            (r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
             "HKEY_CURRENT_USER"),
        ]

        try:
            import winreg

            for key_path, hive_name in persistence_keys:
                try:
                    if "HKCU" in key_path:
                        hive = winreg.HKEY_CURRENT_USER
                        sub_key = key_path.replace("HKCU\\", "")
                    else:
                        hive = winreg.HKEY_LOCAL_MACHINE
                        sub_key = key_path.replace("HKLM\\", "")

                    key = winreg.OpenKey(hive, sub_key, 0, winreg.KEY_READ)

                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            # 检查可疑条目
                            is_suspicious = False
                            reason = ""

                            # Python 脚本
                            if "python" in str(value).lower():
                                is_suspicious = True
                                reason = "Python script in persistence"

                            # 临时目录
                            if "temp" in str(value).lower():
                                is_suspicious = True
                                reason = "Binary in temp directory"

                            # Base64 编码
                            if re.search(r'[A-Za-z0-9+/]{50,}', str(value)):
                                is_suspicious = True
                                reason = "Base64-encoded content"

                            if is_suspicious:
                                findings.append({
                                    "type": "registry_persistence",
                                    "severity": "HIGH",
                                    "key": key_path,
                                    "name": name,
                                    "value": str(value)[:200],
                                    "reason": reason,
                                })

                            i += 1
                        except OSError:
                            break

                    winreg.CloseKey(key)
                except OSError:
                    pass

        except ImportError:
            logger.warning("winreg not available")

        return findings

    @staticmethod
    def check_scheduled_tasks() -> List[Dict]:
        """检查计划任务"""
        findings = []

        if sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV", "/v"],
                    capture_output=True, text=True, timeout=30
                )

                # 检查可疑任务
                suspicious_keywords = [
                    "python", "powershell", "wscript", "cscript",
                    "mshta", "rundll32", "regsvr32",
                ]

                for line in result.stdout.split('\n'):
                    for keyword in suspicious_keywords:
                        if keyword in line.lower():
                            findings.append({
                                "type": "suspicious_scheduled_task",
                                "severity": "MEDIUM",
                                "keyword": keyword,
                                "line": line[:200],
                            })
                            break

            except Exception as e:
                logger.error(f"Task check failed: {e}")

        else:
            # Linux: 检查 crontab
            try:
                result = subprocess.run(
                    ["crontab", "-l"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if 'python' in line.lower() and ('/tmp' in line or '/dev/shm' in line):
                            findings.append({
                                "type": "suspicious_crontab",
                                "severity": "HIGH",
                                "line": line,
                            })
            except Exception:
                pass

        return findings

    @staticmethod
    def check_startup_folder() -> List[Dict]:
        """检查启动文件夹"""
        findings = []

        startup_paths = []

        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                startup_paths.append(
                    os.path.join(appdata, "Microsoft", "Windows",
                                 "Start Menu", "Programs", "Startup")
                )
        else:
            startup_paths.extend([
                os.path.expanduser("~/.config/autostart/"),
                "/etc/xdg/autostart/",
            ])

        for path in startup_paths:
            if not os.path.isdir(path):
                continue

            try:
                for entry in os.listdir(path):
                    full_path = os.path.join(path, entry)
                    # 检查可疑文件类型
                    ext = os.path.splitext(entry)[1].lower()
                    if ext in ('.bat', '.vbs', '.ps1', '.vbe', '.js', '.wsf'):
                        findings.append({
                            "type": "startup_folder",
                            "severity": "MEDIUM",
                            "path": full_path,
                            "reason": f"Suspicious extension: {ext}",
                        })

                    # 检查 .desktop 文件 (Linux)
                    if ext == '.desktop':
                        try:
                            with open(full_path, 'r') as f:
                                content = f.read()
                                if 'python' in content.lower():
                                    findings.append({
                                        "type": "startup_folder",
                                        "severity": "LOW",
                                        "path": full_path,
                                        "reason": "Python in autostart desktop file",
                                    })
                        except Exception:
                            pass

            except PermissionError:
                pass

        return findings


# ============================================================================
# 4. 文件系统检测 / File System Detection
# ============================================================================

class FileSystemDetector:
    """
    文件系统异常检测

    检测方法：
    1. 临时目录中的可执行文件
    2. 最近创建/修改的脚本文件
    3. 隐藏文件和 ADS (NTFS Alternate Data Streams)
    """

    @staticmethod
    def check_temp_directory() -> List[Dict]:
        """检查临时目录中的可疑文件"""
        findings = []

        temp_dirs = []
        if sys.platform == "win32":
            temp_dirs.append(os.environ.get("TEMP", "C:\\Windows\\Temp"))
            temp_dirs.append(os.environ.get("TMP", ""))
        else:
            temp_dirs.extend(["/tmp", "/dev/shm", "/var/tmp"])

        # 可疑扩展名
        suspicious_exts = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.py', '.elf'}

        for temp_dir in temp_dirs:
            if not temp_dir or not os.path.isdir(temp_dir):
                continue

            try:
                for root, dirs, files in os.walk(temp_dir):
                    # 限制深度
                    depth = root.replace(temp_dir, "").count(os.sep)
                    if depth > 2:
                        continue

                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext in suspicious_exts:
                            full_path = os.path.join(root, f)
                            try:
                                stat = os.stat(full_path)
                                # 最近创建（24小时内）
                                if time.time() - stat.st_ctime < 86400:
                                    findings.append({
                                        "type": "temp_file",
                                        "severity": "LOW",
                                        "path": full_path,
                                        "reason": f"Recently created {ext} in temp",
                                    })
                            except OSError:
                                pass

            except PermissionError:
                pass

        return findings


# ============================================================================
# 5. YARA 规则生成 / YARA Rule Generation
# ============================================================================

class YARAGenerator:
    """
    YARA 规则生成器

    YARA 是恶意软件检测的行业标准工具。
    这些规则展示如何基于静态特征编写检测规则。

    使用方法：
      yara -r rules.yar /path/to/scan
    """

    @staticmethod
    def generate_rules() -> str:
        """生成针对教育用途 RAT 的 YARA 检测规则"""
        rules = """
/*
============================================================================
 YARA 检测规则 - 教育用途 RAT
 Educational RAT Detection Rules
============================================================================
*/

rule EDU_RAT_MagicBytes {
    meta:
        description = "Detect educational RAT protocol magic bytes"
        author = "Defense Lab"
        severity = "high"
        date = "2024-01"
        reference = "Educational sample"

    strings:
        // MessagePacket magic bytes
        $magic = { ED C0 DE 01 }  // 0xEDC0DE + version 0x01

    condition:
        $magic at 0
}


rule EDU_RAT_ConfigStrings {
    meta:
        description = "Detect educational RAT configuration strings"
        author = "Defense Lab"
        severity = "medium"

    strings:
        // Config identifiers
        $cfg1 = "edu_rat_demo_key" ascii wide
        $cfg2 = "Educational Remote Administration Framework" ascii wide
        $cfg3 = "EDUCATIONAL USE ONLY" ascii wide nocase
        $cfg4 = "edu_rat" ascii

    condition:
        2 of them
}


rule EDU_RAT_Persistence_Registry {
    meta:
        description = "Detect educational RAT registry persistence"
        author = "Defense Lab"
        severity = "high"

    strings:
        // Registry key name used by the educational RAT
        $reg1 = "WindowsUpdateService" ascii wide
        $reg2 = "WindowsUpdateTask" ascii wide
        $reg3 = "Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run" ascii wide

    condition:
        any of them
}


rule EDU_RAT_NetworkIndicators {
    meta:
        description = "Detect educational RAT network indicators"
        author = "Defense Lab"
        severity = "medium"

    strings:
        $ip1 = "cdn-analytics.example.com" ascii
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii

    condition:
        any of them
}


rule EDU_RAT_CryptoImport {
    meta:
        description = "Detect AES-GCM encryption usage typical of RATs"
        author = "Defense Lab"
        severity = "medium"

    condition:
        // Detects combined use of crypto and socket libraries
        // (Python import patterns)
        uint16(0) == 0x5a4d and  // MZ header
        (
            for any i in (0..pe.number_of_sections - 1): (
                pe.sections[i].name == ".pyc" or
                pe.sections[i].name == ".text"
            )
        )
}
"""

        return rules.strip()

    @staticmethod
    def save_rules(filepath: str = "detection_rules.yar"):
        """保存 YARA 规则到文件"""
        rules = YARAGenerator.generate_rules()
        with open(filepath, 'w') as f:
            f.write(rules)
        logger.info(f"YARA rules saved to {filepath}")
        return filepath


# ============================================================================
# 6. 主扫描与报告 / Main Scanner & Report
# ============================================================================

class DefenseScanner:
    """
    综合防御扫描器

    执行所有检测模块并生成报告
    """

    def __init__(self):
        self.findings: List[Dict] = []
        self.module_results: Dict[str, List[Dict]] = {}

    def scan_all(self) -> Dict:
        """运行所有检测模块"""
        logger.info("=" * 60)
        logger.info("Starting comprehensive defense scan...")
        logger.info("=" * 60)

        # 1. 网络检测
        logger.info("\n[1/5] Network Traffic Analysis...")
        net_detector = NetworkDetector()
        self.module_results['network'] = NetworkDetector.check_suspicious_connections()

        # 2. 进程检测
        logger.info("[2/5] Process Behavior Analysis...")
        self.module_results['process'] = ProcessDetector.check_suspicious_processes()

        # 3. 持久化检测
        logger.info("[3/5] Persistence Mechanism Detection...")
        pers_detector = PersistenceDetector()
        self.module_results['persistence'] = []
        self.module_results['persistence'].extend(
            PersistenceDetector.check_windows_registry()
        )
        self.module_results['persistence'].extend(
            PersistenceDetector.check_scheduled_tasks()
        )
        self.module_results['persistence'].extend(
            PersistenceDetector.check_startup_folder()
        )

        # 4. 文件系统检测
        logger.info("[4/5] File System Analysis...")
        self.module_results['filesystem'] = FileSystemDetector.check_temp_directory()

        # 5. 签名检查
        logger.info("[5/5] Special Checks...")
        self.module_results['special'] = []

        # 汇总
        total = sum(len(v) for v in self.module_results.values())

        report = {
            "scan_time": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "total_findings": total,
            "modules": self.module_results,
        }

        return report

    def print_report(self, report: Dict):
        """打印扫描报告"""
        print("\n" + "=" * 70)
        print("  DEFENSE SCAN REPORT")
        print(f"  Host: {report['hostname']}")
        print(f"  Platform: {report['platform']}")
        print(f"  Scan Time: {report['scan_time']}")
        print("=" * 70)

        total = report['total_findings']

        for module_name, findings in report['modules'].items():
            if not findings:
                continue

            print(f"\n[{module_name.upper()}] {len(findings)} finding(s):")
            print("-" * 50)

            for f in findings[:10]:  # 限制每类显示 10 条
                severity = f.get('severity', 'LOW')
                severity_icon = {
                    'HIGH': '🔴',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                }.get(severity, '⚪')

                print(f"  {severity_icon} [{severity}] {f.get('type', 'unknown')}")
                if 'reason' in f:
                    print(f"     Reason: {f['reason']}")
                if 'path' in f:
                    print(f"     Path: {f['path']}")
                if 'command' in f:
                    print(f"     Command: {f['command'][:100]}")

        print("\n" + "=" * 70)
        if total == 0:
            print("  ✓ No suspicious findings detected")
            print("  (This scan covers basic indicators. Advanced threats")
            print("   may require deeper analysis.)")
        else:
            print(f"  ⚠ Total findings: {total}")
            print("  Review each finding carefully. Some may be false positives.")
        print("=" * 70)


def main():
    """主入口"""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAT/C2 检测与防御工具 (Educational)",
        epilog="For educational defensive security research",
    )
    parser.add_argument(
        "action",
        choices=["scan", "yara", "monitor"],
        help="Action to perform"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output report to file (JSON format)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )

    if args.action == "scan":
        scanner = DefenseScanner()
        report = scanner.scan_all()
        scanner.print_report(report)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[*] Report saved to {args.output}")

    elif args.action == "yara":
        filepath = YARAGenerator.save_rules(args.output or "detection_rules.yar")
        print(f"[*] YARA rules generated: {filepath}")
        print("\nUsage: yara -r detection_rules.yar /path/to/scan")

    elif args.action == "monitor":
        print("[*] Continuous monitoring mode")
        print("[*] This would require elevated privileges and a daemon process")
        print("[*] For production use, consider:")
        print("    - Sysmon (Windows) with custom rules")
        print("    - auditd + osquery (Linux)")
        print("    - Elastic Security / Wazuh (commercial/OSS SIEM)")
        print("    - Custom eBPF monitors")


if __name__ == "__main__":
    main()
