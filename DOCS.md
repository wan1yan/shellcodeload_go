# Codeload 架构与原理解析

本文档将深入探讨 **Codeload** 中使用的技术实现和规避策略。

## 高层架构

加载器通过四个不同的阶段来确保隐蔽性和可靠性：

1.  **系统审计 (执行前)**: 模拟良性用户行为并检查环境完整性。
2.  **环境验证**: 验证硬件和运行时间指标以检测沙箱。
3.  **安全获取**: 使用伪造的 TLS 指纹下载 Payload。
4.  **隐蔽执行**: 解密 Payload 并使用间接系统调用和纤程（Fiber）执行它。

---

## 1. 核心注入引擎 (`injector.go`)

注入引擎负责内存管理和执行。它避免使用像 `VirtualAlloc` 或 `CreateThread` 这样被严密监控的标准 Win32 API。

### 间接系统调用 (Indirect Syscalls)
加载器不直接调用 `NtAllocateVirtualMemory`（这会经过可能被 Hook 的 `ntdll.dll`），而是：
1.  动态解析系统服务号 (SSN)（参见下文 *Bananaphone*）。
2.  在合法的 `ntdll.dll` 内存空间内定位 `syscall; ret` gadget。
3.  通过此 gadget 执行系统调用。
这使得调用栈看起来源自合法的内存区域 (ntdll)，从而混淆 EDR 的调用栈回溯分析。

### 纤程执行 (Fiber Execution)
线程是 EDR 监控的主要目标。**纤程 (Fiber)** 是由应用程序手动调度的轻量级执行单元。
*   **机制**: 加载器将主线程转换为纤程 (`ConvertThreadToFiber`) 并为 Shellcode 创建一个新的纤程 (`CreateFiber`)。
*   **优势**: 相比于线程创建，许多安全产品对纤程切换的可见性较低。

### 智能休眠 (Smart Sleep)
传统的 `Sleep()` 很容易暴露。Codeload 实现了自定义的“智能休眠”：
1.  **加密**: 在休眠前，对 Shellcode 内存区域进行 XOR 加密。
2.  **保护**: 内存权限从 `RX`（执行）更改为 `RW`（读/写）。这可以向寻找可执行私有内存的扫描器隐藏可执行代码。
3.  **等待**: 使用 `WaitForSingleObject` 等待一个可等待计时器（而不是 `Sleep`）。
4.  **恢复**: 唤醒后，解密内存并将权限恢复为 `RX`。

---

## 2. 动态 SSN 解析 (`netcache/`)

该模块（内部命名为 "ApplePhone" 或 "Bananaphone"）实现了 **Halo's Gate** 技术的变体。

### 问题
EDR 通过覆盖 `ntdll.dll` 函数的前导码（写入 `jmp` 指令）来进行 Hook。这阻止了我们直接从本地进程内存中读取 SSN。

### 解决方案
1.  **牺牲进程**: 加载器生成一个挂起的 `svchost.exe` 进程。由于它立即处于挂起状态，EDR 可能尚未注入 Hook（或者加载器直接读取了磁盘映射文件）。
2.  **读取干净的 ntdll**: 它使用 `ReadProcessMemory` 将干净的 `ntdll.dll` 从牺牲进程复制到自己的内存中。
3.  **手动解析**: 它解析此干净副本的导出地址表 (EAT)，以查找 `NtAllocateVirtualMemory` 和 `NtProtectVirtualMemory` 等函数的 SSN。

---

## 3. 网络规避 (`nopoe/update.go`)

网络签名是一种常见的检测向量。Codeload 使用 **uTLS** 来规避 JA3/JA4 指纹识别。

*   **JA3 伪造**: 标准 Go `net/http` 客户端具有独特的 TLS 握手特征。Codeload 使用 `uTLS` 模拟 **Google Chrome** 浏览器的 Client Hello 数据包（加密套件、扩展、曲线等）。
*   **Header 伪造**: 它手动构建 HTTP 请求，并附带与 Windows 10 Chrome 环境匹配的合法 User-Agent、Accept 和 Language 标头。

---

## 4. 反沙箱 (`nopoe/check.go`)

在执行任何恶意逻辑之前，Codeload 会验证环境：
*   **运行时间**: 检查 `GetTickCount64`。如果系统运行时间少于 10 分钟，它可能会假设这是一个沙箱并终止。
*   **CPU 核心**: 检查 `runtime.NumCPU()`。沙箱通常只有 1 个 vCPU。Codeload 要求至少 2 个。
*   **熵稀释**: 二进制文件包含大量良性文本（Apache 许可证），以降低文件的熵值并改变其哈希值，从而绕过基于高熵（加壳代码）的静态签名。

---

## 5. 密码学 (`crypto.go`)

Payload 使用 **ChaCha20-Poly1305** 加密，这是一种现代、高速且带认证的流密码。
*   **格式**: Payload Blob 包含 `[Nonce] [Ciphertext] [Key]`。
*   **流程**: 加载器从下载的 Blob 中提取密钥和随机数 (Nonce)，以在内存中解密 Shellcode。

---
