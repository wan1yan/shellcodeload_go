# ShellcodeLoad-Go

一款基于 Go 语言开发的高级 Windows Shellcode 加载器，集成了多种现代红队规避（Evasion）与对抗技术。本项目仅供合法的安全研究与授权渗透测试使用。

## 核心特性

- **直接系统调用 (Direct Syscalls)**: 通过汇编实现，绕过用户态 API 钩子 (Inline Hooks)。
- **堆栈欺骗 (Stack Spoofing)**: 模拟合法的调用堆栈，规避基于调用栈分析的检测。
- **内存保护切换 (RW -> RX)**: 采用两阶段内存分配方案，避免分配明显的 RWX 内存。
- **纤程执行 (Fiber Execution)**: 利用 Windows Fiber 机制在用户态执行载荷，具有独立的上下文和规避特性。
- **睡眠掩码 (Smart Sleep/Sleep Masking)**: 在睡眠期间对内存中的载荷进行加密并修改内存属性（RW），规避内存扫描。
- **动态 SSN 解析**: 运行时动态获取系统调用号（SSN），不依赖硬编码。
- **反调试与反沙箱**: 集成多种环境检测逻辑，识别调试器、虚拟机及沙箱环境。
- **载荷解密**: 支持 ChaCha20 加密载荷的远程获取与实时解密。

## 快速开始

1. **环境准备**: 安装 Go 环境（建议 1.20+）并配置好 Windows 交叉编译环境。
2. **配置 URL**: 修改 `main.go` 中的 `configURL` 为你的 C2 配置文件地址。
3. **编译**:
   ```bash
   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o loader.exe
   ```
## vt检测图:
![photo_6337066581753532155_w](https://github.com/user-attachments/assets/955229d0-bf55-4ed1-b153-014529ddfe31)

## 测试360动静无感
<img width="1355" height="829" alt="image" src="https://github.com/user-attachments/assets/890cdfeb-945a-4d88-87c3-64c7abb351b3" />

## 使用手册

https://github.com/wan1yan/shellcodeload_go/blob/main/%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8C.md

## 说明文档

https://github.com/wan1yan/shellcodeload_go/tree/main#:~:text=6%20hours%20ago-,%E8%AF%B4%E6%98%8E%E6%96%87%E6%A1%A3.md,-Initial%20commit%3A%20Advanced

## 免责声明

本工具仅用于安全研究与学习。使用者需遵守当地法律法规，严禁用于任何非法用途。作者不对因使用本工具造成的任何后果负责。
