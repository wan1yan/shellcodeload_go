# Codeload 项目说明文档

## 1. 项目简介
**Codeload** 是一款专为红队行动和安全研究设计的高级隐蔽型 Windows Shellcode 加载器与注入器。它集成了多项尖端的规避技术，通过模块化设计实现了针对不同对抗环境的灵活切换。

## 2. 核心技术特性

### 2.1 模块化规避改造
项目支持通过 Go Build Tags (`sandbox`, `evasion`, `debug`) 动态启用或禁用规避功能：
- **物理隔离**: 未启用相关标签时，敏感逻辑和特征字符串（如反沙箱指纹、ETW 补丁地址等）在代码层面完全不参与编译。
- **零指纹**: Release 版本（无标签）在二进制层面实现了特征抹除，检出率极低。

### 2.2 间接系统调用 (Indirect Syscalls)
- **原理**: 绕过用户模式下的 API Hooking。加载器不直接调用 `VirtualAlloc` 等高敏 API，而是定位 `ntdll.dll` 中的 `syscall; ret` 指令序列。
- **动态 SSN 解析**: 采用 **Halo's Gate** 变体技术，通过生成一个牺牲进程（如 `svchost.exe`）并读取其内存中的干净 `ntdll.dll` 副本，动态解析系统服务号 (SSN)。

### 2.3 调用栈欺骗 (Stack Spoofing)
- **原理**: 混淆 EDR 的调用栈回溯分析。
- **实现**: 修改底层汇编实现，在系统调用前手动构造栈帧，将栈顶伪造为 `ntdll` 内部的合法地址。
- **优化**: 解决了栈平衡恢复问题，通过精确计算偏移量并利用硬编码字节码绕过汇编器检查，确保了程序执行的稳定性。

### 2.4 ETW 屏蔽 (ETW Blinding)
- **功能**: 运行时 Patch `ntdll!EtwEventWrite` 函数，将其入口修改为 `RET` 指令，从而阻断 EDR 获取进程运行时的遥测数据。

### 2.5 智能休眠 (Smart Sleep)
- **功能**: 在休眠期间对 Shellcode 内存区域进行 XOR 加密，并将权限从 `RX` 降级为 `RW`，唤醒时再解密还原。有效对抗内存扫描器。

### 2.6 流量伪装 (uTLS)
- **功能**: 模拟主流浏览器（如 Chrome）的 TLS Client Hello 指纹，规避基于网络指纹特征的流量监控。

---

## 3. 项目架构说明

| 模块路径 | 功能描述 |
| :--- | :--- |
| `main.go` | 程序主逻辑，负责加载流程编排、配置获取及 Payload 下载。 |
| `internal/check/` | **环境检测模块**。受 `sandbox` 标签控制，包含开机时间、CPU 核心数、用户指纹等检查。 |
| `internal/evasion/` | **规避增强模块**。受 `evasion` 标签控制，实现 ETW 屏蔽和系统调用 Gadget 定位。 |
| `internal/log/` | **日志系统**。受 `debug` 标签控制，实现 Release 零输出与 Debug 实时反馈的物理隔离。 |
| `netcache/` | 底层 SSN 解析引擎 (Bananaphone/Halo's Gate)。 |
| `injector.go` | 核心注入引擎，负责内存分配、Fiber 切换及 Syscall 调用。 |
| `crypto.go` | Payload 解密逻辑 (ChaCha20-Poly1305)。 |
| `syscalls_windows_amd64.s` | 底层汇编实现，包含自定义的 Stack Spoofing 逻辑。 |

---

## 4. 规避逻辑详解

### 4.1 反沙箱检查 (Internal Check)
在 `sandbox` 模式下，程序会检查以下项，任一项不满足则静默退出：
1. **运行时间**: 检查系统开机时长是否超过 10 分钟。
2. **硬件特征**: 检查 CPU 核心数是否少于 2 核。
3. **环境指纹**: 检查分辨率、管理员权限等。

### 4.2 注入流程 (Execution Flow)
1. **获取配置**: 从远程 URL 下载加密 Payload 的位置信息。
2. **下载 Payload**: 采用 uTLS 指纹下载加密的 Shellcode。
3. **解密**: 使用 ChaCha20-Poly1305 算法解密，Payload 格式含混淆填充及长度校验。
4. **注入执行**: 分配内存 -> 写入 -> 修改权限 -> 切换至 **Fiber（纤程）** 模式运行，最大程度规避线程级监控。
