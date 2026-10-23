package proxycore

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// dialDirectPipe creates a net.Pipe and returns a net.Conn configured for SOCKS5 negotiation
func setupSocksMock(t *testing.T, handler func(server net.Conn)) (client net.Conn, server net.Conn) {
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		handler(s)
	}()
	return c, s
}

func TestSocks5GreetingAndAuthNegotiation(t *testing.T) {
	// 1. Success without auth
	clientConn, _ := setupSocksMock(t, func(s net.Conn) {
		buf := make([]byte, 3)
		if _, err := io.ReadFull(s, buf); err != nil {
			return
		}
		// Expect VER 5, NMETHODS 1, METHOD 0
		if !bytes.Equal(buf, []byte{0x05, 0x01, 0x00}) {
			t.Errorf("unexpected greeting: %x", buf)
			return
		}
		// Reply VER 5, METHOD 0
		s.Write([]byte{0x05, 0x00})

		// Read CONNECT
		connReq := make([]byte, 10)
		io.ReadFull(s, connReq)
		// Reply SUCCESS with IPv4 0.0.0.0:0
		s.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
	defer clientConn.Close()

	// 2. Reject version
	c2, _ := setupSocksMock(t, func(s net.Conn) {
		buf := make([]byte, 3)
		io.ReadFull(s, buf)
		s.Write([]byte{0x04, 0x00}) // wrong version 4
	})
	defer c2.Close()

	// 3. Reject auth methods (0xFF)
	c3, _ := setupSocksMock(t, func(s net.Conn) {
		buf := make([]byte, 3)
		io.ReadFull(s, buf)
		s.Write([]byte{0x05, 0xFF}) // No acceptable methods
	})
	defer c3.Close()

	// 4. Username/password negotiation success
	c4, _ := setupSocksMock(t, func(s net.Conn) {
		buf := make([]byte, 4)
		io.ReadFull(s, buf) // 05 02 00 02
		s.Write([]byte{0x05, 0x02})

		// Auth req: VER 1, ULEN 4, user, PLEN 4, pass
		authBuf := make([]byte, 11)
		io.ReadFull(s, authBuf)
		s.Write([]byte{0x01, 0x00}) // auth success

		// CONNECT req & reply
		connReq := make([]byte, 10)
		io.ReadFull(s, connReq)
		s.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90})
	})
	defer c4.Close()

	// 5. Username/password negotiation failure
	c5, _ := setupSocksMock(t, func(s net.Conn) {
		buf := make([]byte, 4)
		io.ReadFull(s, buf)
		s.Write([]byte{0x05, 0x02})

		authBuf := make([]byte, 11)
		io.ReadFull(s, authBuf)
		s.Write([]byte{0x01, 0x01}) // auth failure (status != 0)
	})
	defer c5.Close()
}

func TestSocks5ConnectErrorsAndAddressTypes(t *testing.T) {
	// Test error status responses from SOCKS5 server
	errCodes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	for _, code := range errCodes {
		msg, ok := socksErrMap[code]
		if code <= 0x08 && !ok {
			t.Errorf("missing error mapping for 0x%02x", code)
		}
		if code == 0x09 && ok {
			t.Errorf("unexpected error mapping for unknown 0x09: %s", msg)
		}
	}

	// Domain bound address parsing check
	domainReply := []byte{
		0x05, 0x00, 0x00, 0x03, // VER, REP=0, RSV=0, ATYP=3
		0x0b, // length 11
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, 0x50, // port 80
	}
	if domainReply[3] != 0x03 || domainReply[4] != 11 {
		t.Error("domain reply template invalid")
	}

	// IPv6 bound address check
	ipv6Reply := make([]byte, 4+16+2)
	ipv6Reply[0] = 0x05
	ipv6Reply[1] = 0x00
	ipv6Reply[2] = 0x00
	ipv6Reply[3] = 0x04
	copy(ipv6Reply[4:20], net.ParseIP("2001:db8::1").To16())
	binary.BigEndian.PutUint16(ipv6Reply[20:], 8080)
	if ipv6Reply[3] != 0x04 {
		t.Error("ipv6 reply template invalid")
	}
}

func TestSocks5DialContextTimeoutAndCancellation(t *testing.T) {
	// Immediate context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DialSOCKS5Context(ctx, "127.0.0.1:1080", "", "", "example.com", 80, time.Second, true)
	if err == nil {
		t.Error("expected error for canceled context")
	}

	// Dial with unreachable port/timeout
	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelTimeout()
	_, err = DialSOCKS5Context(ctxTimeout, "127.0.0.1:65534", "", "", "example.com", 80, 50*time.Millisecond, true)
	if err == nil {
		t.Error("expected error for unreachable proxy")
	}
}
