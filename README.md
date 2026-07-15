# 教育用途远程管理框架 (Educational RAT Framework)

> ⚠️ **法律声明**: 本项目**仅供**网络安全教育、授权渗透测试和防御研究使用。未经授权对他人系统使用属于违法行为，使用者须自行承担全部法律责任。

## 项目概述

这是一个完整的远程管理框架（常被称为 RAT - Remote Administration Tool），专为网络安全专业学生设计。项目从**攻击方视角**构建，同时每个部分都标注了**防守方检测点**，帮助你建立攻防一体的思维模式。

### 学习目标

| 模块 | 攻击方学习 | 防守方学习 |
|------|-----------|-----------|
| **加密通信** | AES-GCM 对称加密、ECDH 密钥交换 | 流量熵值分析、JA3/JARM 指纹检测 |
| **C2 架构** | 多客户端管理、心跳检测、命令分发 | 异常外连检测、心跳模式识别 |
| **命令执行** | Shell 执行、文件操作、进程管理 | API hooking、Sysmon 事件监控 |
| **持久化** | 注册表、计划任务、启动目录 | Autoruns、注册表审计、Event ID 4698 |
| **反分析** | 沙箱检测、调试器检测 | 沙箱改进、反反调试技术 |

## 项目结构

```
edu_rat/
├── README.md              # 本文件
├── config.py              # 全局配置（连接、加密、持久化）
├── crypto_utils.py        # 加密模块（AES-GCM、ECDH、消息协议、流量混淆）
├── commands.py            # 命令执行模块（Shell、文件、进程、网络扫描、截图）
├── server.py              # C2 服务端（多客户端管理、Web API、SQLite 持久化）
├── client.py              # 客户端代理（注册、心跳、命令执行、重连、持久化）
└── defense_detect.py      # 防守检测脚本（网络/进程/持久化/文件/YARA）
```

## 快速开始

### 1. 安装依赖

```bash
pip install cryptography psutil pillow aiohttp mss
```

### 2. 运行加密模块自测

```bash
python crypto_utils.py
```

输出示例：
```
============================================================
加密模块自测 / Crypto Module Self-Test
============================================================

[1] AES-256-GCM 加解密测试
    ✓ 加解密成功
[2] 消息协议序列化测试
    ✓ 序列化/反序列化成功
[3] 安全通道端到端测试
    ✓ 安全通道通信成功
[4] HMAC 完整性校验测试
    ✓ HMAC 校验成功
[5] ECDH 密钥交换测试
    ✓ ECDH 密钥交换成功
[6] 流量混淆测试
    ✓ 流量伪装成功
============================================================
所有测试通过！
============================================================
```

### 3. 运行命令模块自测

```bash
python commands.py
```

### 4. 启动 C2 服务端

```bash
python server.py
```

### 5. 启动客户端（另一个终端）

```bash
python client.py --host 127.0.0.1 --port 8443
```

### 6. 运行防守检测

```bash
# 系统扫描
python defense_detect.py scan

# 生成 YARA 检测规则
python defense_detect.py yara
```

## 核心技术详解

### 通信加密 (AES-256-GCM)

```
┌─────────────────────────────────────────────────────┐
│              加密消息格式                             │
│  ┌──────────┬──────────────────────────────────┐    │
│  │ Nonce    │ Ciphertext (AES-GCM)             │    │
│  │ (12 B)   │ (Payload + Auth Tag 16B)        │    │
│  └──────────┴──────────────────────────────────┘    │
│                                                      │
│  GCM 模式同时提供：                                   │
│  - 机密性（加密）                                    │
│  - 完整性（认证标签）                                │
│  - 防篡改（任何修改都会导致解密失败）                │
└─────────────────────────────────────────────────────┘
```

### 消息协议 (二进制格式)

```
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│ Magic    │ Version  │ Type     │ Seq#     │Timestamp │ PayLen   │ Payload  │
│ 0xEDC0DE │   0x01   │ 1B       │ 4B       │ 8B       │ 4B       │ variable │
│ (4B)     │  (1B)    │          │          │(μs)      │          │          │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘

防守检测点: Magic 字节 0xEDC0DE 可用于 Snort/Suricata IDS 规则匹配
```

### 心跳检测原理

```
客户端                          服务端
  │                               │
  │──── HEARTBEAT ───────────────>│  每 30s（含随机抖动）
  │<─── ACK + [待执行命令] ──────│  响应同时下发排队命令
  │                               │
  │  4x 心跳无响应 → 判定超时    │
```

## 防守检测清单

使用 `defense_detect.py` 可以检测以下威胁指标：

### 🔴 高优先级检测

- [ ] Python 解释器的异常外连（非 80/443/22 端口）
- [ ] 注册表 Run Key 中出现 Python 脚本路径
- [ ] cmd.exe 由非交互进程（如 Office）启动
- [ ] PowerShell 编码命令执行 (`-enc` 参数)
- [ ] 临时目录中存在可执行脚本

### 🟡 中优先级检测

- [ ] 计划任务中执行 Python/PowerShell 脚本
- [ ] 启动文件夹中出现 .bat/.vbs/.ps1 文件
- [ ] certutil 下载行为
- [ ] BITSAdmin 文件传输
- [ ] 异常的计划任务名称（伪装系统任务）

### 🟢 低优先级检测

- [ ] 非标准端口持续连接
- [ ] 临时目录中最近创建的可执行文件
- [ ] 进程枚举频率异常

## 扩展建议

作为网络安全学生，你可以：

1. **强化加密**：实现 ECDH 密钥协商、证书固定 (Certificate Pinning)
2. **协议演进**：将 TCP 替换为 HTTPS/DNS/ICMP 隧道
3. **域前置**：学习 CDN 域前置技术及其检测
4. **DGA**：实现域名生成算法 (Domain Generation Algorithm)
5. **内存执行**：学习反射加载、进程注入等无文件技术
6. **EDR 绕过**：学习 syscall 直接调用、unhooking 等技术
7. **编写检测规则**：为 YARA、Snort、Sigma 编写检测规则
8. **实现 EDR**：基于本项目编写一个简单的端点检测系统

## 参考资源

- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [Red Canary - Threat Detection](https://redcanary.com/threat-detection-report/)
- [SANS - C2 Matrix](https://www.thec2matrix.com/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)

---

**Remember**: With great power comes great responsibility. 仅在授权环境中使用。
