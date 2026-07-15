# 火绒免杀分析报告

> ⚠️ 本报告仅供安全研究教育用途，帮助理解杀软工作原理与防御策略。

## 一、当前代码在火绒面前的检测分析

### 1.1 火绒的检测引擎

火绒安全软件使用**多层检测机制**：

```
┌───────────────────────────────────────────────┐
│              火绒多层检测架构                    │
├───────────────────────────────────────────────┤
│ Layer 1: 静态扫描 (Static Analysis)            │
│   ├─ 文件哈希 (MD5/SHA) 黑名单                │
│   ├─ 字符串特征匹配 (YARA-like)                │
│   ├─ PE 导入表分析 (IAT)                       │
│   └─ 数字签名验证                              │
├───────────────────────────────────────────────┤
│ Layer 2: 启发式分析 (Heuristic Analysis)       │
│   ├─ 代码行为模拟                              │
│   ├─ API 调用序列分析                          │
│   └─ 熵值分析（检测加密/压缩代码）               │
├───────────────────────────────────────────────┤
│ Layer 3: 行为监控 (Behavioral Monitoring)      │
│   ├─ 进程创建监控 (CreateProcess hook)          │
│   ├─ 注册表操作监控                             │
│   ├─ 网络连接监控                               │
│   └─ 文件系统监控                               │
├───────────────────────────────────────────────┤
│ Layer 4: 网络防护 (Network Protection)          │
│   ├─ 异常外连检测                               │
│   ├─ C2 通信模式识别                            │
│   └─ 流量行为分析                               │
└───────────────────────────────────────────────┘
```

### 1.2 原始版客户端 (`client.py`) 在各层的检测结果

| 检测层 | 检测项 | 状态 | 原因 |
|--------|--------|------|------|
| 静态 | 字符串特征 | ❌ **拦截** | 明文含 `edu_rat`、`RAT`、`Educational Remote Administration` 等敏感字符串 |
| 静态 | IAT 导入表 | ❌ **拦截** | 导入 `cryptography`、`subprocess`、`socket` 等敏感库 |
| 静态 | PE 熵值 | ⚠️ 可疑 | PyInstaller 打包的 Python 程序熵值较高 |
| 行为 | shell=True | ❌ **拦截** | `subprocess.run(shell=True)` 被火绒行为监控重点标记 |
| 行为 | 注册表操作 | ❌ **拦截** | `winreg.OpenKey(..., KEY_SET_VALUE)` 触发防护 |
| 行为 | 计划任务 | ❌ **拦截** | `schtasks /create` 命令触发告警 |
| 网络 | 非标准端口 | ❌ **拦截** | 连接 8443 等非标准端口 |
| 网络 | 心跳模式 | ⚠️ 可疑 | 30秒周期的持续外连 |

**结论: 原始版在火绒面前基本无法通过任何一层检测。**

### 1.3 混淆版客户端 (`client_obfuscated.py`) 在各层的检测结果

| 检测层 | 检测项 | 状态 | 原因 |
|--------|--------|------|------|
| 静态 | 字符串特征 | 🟡 **可能通过** | 所有字符串 XOR+Base64 编码，静态扫描无法直接匹配 |
| 静态 | IAT 导入表 | 🟡 **可能通过** | 使用 `__import__()` 动态导入，延迟加载 |
| 静态 | PE 熵值 | ⚠️ 可疑 | 仍较高，但火绒对高熵值仅标记为可疑，不会直接拦截 |
| 行为 | shell=True | ❌ **拦截** | 混淆无法改变 API 调用方式，行为监控仍会拦截 |
| 行为 | 注册表操作 | ❌ **拦截** | 同上 |
| 网络 | 非标准端口 | ❌ **拦截** | 混淆无法改变网络行为 |

**结论: 混淆版可绕过静态扫描，但行为监控和网络防护仍会拦截。**

### 1.4 PyInstaller 打包后的检测变化

PyInstaller 打包成 EXE 后：
- **优势**：Python 字节码被编译，源码不可直接阅读
- **劣势**：PyInstaller 的 bootloader 有固定特征，火绒可通过特征识别这是 PyInstaller 打包的 Python 程序，并重点关注
- **额外**：`--key` 参数可加密字节码，但 `--noconsole` 反而会增加可疑度

## 二、真正绕过火绒需要的技术（学习路线）

### Level 1: 基础静态免杀 ✓ (已实现)
- 字符串编码/加密
- 动态 API 导入
- 代码混淆

### Level 2: API 层面绕过 ⚙️ (需实现)
```
需要绕过用户态 Hook:
├─ NtCreateProcess → 直接 syscall
├─ NtWriteVirtualMemory → 直接 syscall  
├─ NtAllocateVirtualMemory → 直接 syscall
└─ 技术: SysWhispers2 / Hell's Gate / Halo's Gate
```

### Level 3: 行为层面绕过 🔒 (需实现)
```
├─ PPID Spoofing (父进程伪装)
│   将恶意进程的父进程设为 explorer.exe
├─ Process Hollowing (进程镂空)
│   注入合法进程内存空间执行
├─ DLL Side-Loading (DLL 侧加载)
│   利用合法签名的 EXE 加载恶意 DLL
└─ COM Object Hijacking
```

### Level 4: 流量层面绕过 🌐 (需实现)
```
├─ HTTPS + 域前置 (Domain Fronting)
│   伪装成访问 CDN (Cloudflare/AWS CloudFront)
├─ DNS 隧道
│   通过 DNS 查询传输 C2 数据
└─ 协议模拟
│   模仿 Telegram/WeChat 等常见应用的通信模式
```

## 三、实际操作步骤

### 步骤 1: 在 Windows 上打包 EXE

```bash
# 在 Windows 虚拟机中
cd edu_rat
pip install pyinstaller cryptography psutil

# 基础版（调试用，有控制台窗口）
python build_exe.py --mode basic

# 隐蔽版（无窗口，混淆）
python build_exe.py --mode stealth
```

### 步骤 2: 配置 C2 服务器

```bash
# 在你控制的服务器上（需要有公网 IP）
python3 server.py
# 或指定端口: python3 server.py --port 8443
```

### 步骤 3: 修改客户端连接地址

修改 `client_obfuscated.py` 或生成后的 `launcher.bat` 中的 `C2_HOST`。

### 步骤 4: 测试免杀效果

推荐使用在线扫描平台（不上传实际恶意代码，只测试混淆技术）：
- **VirusTotal**: 注意会上传样本并分享给安全厂商
- **nodistribute.com**: 不会分享样本
- **antiscan.me**: 仅供个人使用

## 四、防御视角学习

作为网络安全专业学生，更重要的是理解**如何检测和防御**这类攻击：

```bash
# 在你的环境中运行防守检测
python3 defense_detect.py scan
python3 defense_detect.py yara
```

推荐的防御学习路径：
1. 学习 Sysmon 配置，编写检测规则
2. 使用 Sigma 规则检测可疑行为
3. 搭建 ELK + Osquery 进行端点监控
4. 学习逆向工程分析恶意样本
