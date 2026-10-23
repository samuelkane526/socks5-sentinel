package proxycore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	socksErrMap = map[byte]string{
		0x01: "General SOCKS server failure",
		0x02: "Connection not allowed by ruleset",
		0x03: "Network unreachable",
		0x04: "Host unreachable",
		0x05: "Connection refused",
		0x06: "TTL expired",
		0x07: "Command not supported",
		0x08: "Address type not supported",
	}
)

// DialSOCKS5 connects to a target host and port via a SOCKS5/SOCKS5h proxy with a background context.
func DialSOCKS5(proxyAddr, username, password, targetHost string, targetPort int, timeout time.Duration, resolveRemoteDNS bool) (net.Conn, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return DialSOCKS5Context(ctx, proxyAddr, username, password, targetHost, targetPort, timeout, resolveRemoteDNS)
}

// DialSOCKS5Context connects to targetHost:targetPort via SOCKS5 proxy with context cancellation support.
func DialSOCKS5Context(ctx context.Context, proxyAddr, username, password, targetHost string, targetPort int, timeout time.Duration, resolveRemoteDNS bool) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	// Close conn immediately if context cancels while performing SOCKS handshake
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// 1. Client Greeting
	var greet []byte
	if username != "" && password != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02} // SOCKS5, 2 methods: No Auth (0x00) & User/Pass (0x02)
	} else {
		greet = []byte{0x05, 0x01, 0x00} // SOCKS5, 1 method: No Auth (0x00)
	}

	if _, err := conn.Write(greet); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed sending SOCKS5 greeting: %w", err)
	}

	// 2. Server Method Selection Response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed reading SOCKS5 greeting response: %w", err)
	}

	if resp[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid SOCKS version from server: 0x%02x", resp[0])
	}

	method := resp[1]
	if method == 0xFF {
		_ = conn.Close()
		return nil, errors.New("SOCKS5 proxy rejected authentication methods (0xFF)")
	}

	// 3. RFC 1929 Username/Password Authentication if required
	if method == 0x02 {
		if username == "" || password == "" {
			_ = conn.Close()
			return nil, errors.New("proxy requires authentication credentials, but none provided")
		}

		ulen := len(username)
		plen := len(password)
		if ulen > 255 || plen > 255 {
			_ = conn.Close()
			return nil, errors.New("username or password exceeds 255 bytes")
		}

		authReq := make([]byte, 0, 3+ulen+plen)
		authReq = append(authReq, 0x01, byte(ulen))
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(plen))
		authReq = append(authReq, []byte(password)...)

		if _, err := conn.Write(authReq); err != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("failed sending SOCKS5 auth credentials: %w", err)
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("failed reading SOCKS5 auth response: %w", err)
		}

		if authResp[1] != 0x00 {
			_ = conn.Close()
			return nil, fmt.Errorf("SOCKS5 authentication failed (status: 0x%02x)", authResp[1])
		}
	} else if method != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS5 auth method: 0x%02x", method)
	}

	// 4. Send CONNECT Command
	targetIP := net.ParseIP(targetHost)

	var req []byte
	req = append(req, 0x05, 0x01, 0x00) // VER 5, CMD 1 (CONNECT), RSV 0

	if resolveRemoteDNS || targetIP == nil {
		// ATYP 0x03: Domain Name (Forced remote DNS resolution)
		if len(targetHost) > 255 {
			_ = conn.Close()
			return nil, errors.New("target host domain length exceeds 255 characters")
		}
		req = append(req, 0x03, byte(len(targetHost)))
		req = append(req, []byte(targetHost)...)
	} else if ip4 := targetIP.To4(); ip4 != nil {
		// ATYP 0x01: IPv4
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip6 := targetIP.To16(); ip6 != nil {
		// ATYP 0x04: IPv6
		req = append(req, 0x04)
		req = append(req, ip6...)
	} else {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid target host format: %s", targetHost)
	}

	// Port: 2 bytes Big Endian
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	req = append(req, portBuf...)

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed sending SOCKS5 CONNECT command: %w", err)
	}

	// 5. Read Server Reply
	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed reading SOCKS5 CONNECT reply header: %w", err)
	}

	if replyHeader[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid SOCKS reply version: 0x%02x", replyHeader[0])
	}

	rep := replyHeader[1]
	if rep != 0x00 {
		_ = conn.Close()
		msg, ok := socksErrMap[rep]
		if !ok {
			msg = fmt.Sprintf("Unknown error (0x%02x)", rep)
		}
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %s", msg)
	}

	atyp := replyHeader[3]
	var addrLen int

	switch atyp {
	case 0x01: // IPv4
		addrLen = 4 + 2 // 4 bytes IP + 2 bytes Port
	case 0x03: // Domain name
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLenBuf); err != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("failed reading bound domain length: %w", err)
		}
		addrLen = int(domainLenBuf[0]) + 2
	case 0x04: // IPv6
		addrLen = 16 + 2 // 16 bytes IP + 2 bytes Port
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS reply address type: 0x%02x", atyp)
	}

	boundAddr := make([]byte, addrLen)
	if _, err := io.ReadFull(conn, boundAddr); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed reading bound address: %w", err)
	}

	// Reset deadline so caller has full control of timeouts
	_ = conn.SetDeadline(time.Time{})

	return conn, nil
}
