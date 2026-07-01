package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// startUDPEchoServer runs a UDP server that echoes any datagram back to its
// sender. It stands in for the real target the client wants to reach.
func startUDPEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr)
}

// startFakeSocksUDPUpstream emulates a SOCKS5 proxy that supports UDP
// ASSOCIATE: it completes the no-auth + associate handshake on TCP, then runs a
// UDP relay that unwraps the SOCKS5 UDP header, forwards the payload to the
// embedded DST.ADDR/PORT, and re-wraps the reply. Returns its socks5:// URL.
func startFakeSocksUDPUpstream(t *testing.T) string {
	t.Helper()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcpLn.Close() })

	udpRelay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpRelay.Close() })

	relayPort := udpRelay.LocalAddr().(*net.UDPAddr).Port

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go fakeUpstreamHandshake(conn, relayPort)
		}
	}()

	go fakeUpstreamRelay(t, udpRelay)

	return fmt.Sprintf("socks5://%s", tcpLn.Addr().String())
}

func fakeUpstreamHandshake(conn net.Conn, relayPort int) {
	defer conn.Close()

	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socksVersion5, socksMethodNoAuth}); err != nil {
		return
	}

	req := make([]byte, 10)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != socksCmdUDPAssociate {
		return
	}

	// Reply with BND.ADDR 127.0.0.1 : relayPort.
	out := []byte{socksVersion5, socksReplySuccess, 0x00, socksAtypIPv4, 127, 0, 0, 1}
	out = binary.BigEndian.AppendUint16(out, uint16(relayPort))
	if _, err := conn.Write(out); err != nil {
		return
	}

	// Hold the control connection open until the client tears it down.
	_, _ = io.Copy(io.Discard, conn)
}

func fakeUpstreamRelay(t *testing.T, relay *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}

		dstIP, dstPort, payloadOff, err := parseSocksUDPHeader(buf[:n])
		if err != nil {
			t.Errorf("fake upstream parse header: %s", err)
			continue
		}

		target := &net.UDPAddr{IP: dstIP, Port: dstPort}
		out, err := net.DialUDP("udp", nil, target)
		if err != nil {
			t.Errorf("fake upstream dial target: %s", err)
			continue
		}

		if _, err := out.Write(buf[payloadOff:n]); err != nil {
			out.Close()
			continue
		}
		_ = out.SetReadDeadline(time.Now().Add(5 * time.Second))
		reply := make([]byte, 64*1024)
		rn, err := out.Read(reply)
		out.Close()
		if err != nil {
			continue
		}

		// Re-wrap with the same SOCKS5 UDP header (header bytes are unchanged).
		wrapped := append([]byte{}, buf[:payloadOff]...)
		wrapped = append(wrapped, reply[:rn]...)
		if _, err := relay.WriteToUDP(wrapped, from); err != nil {
			return
		}
	}
}

func parseSocksUDPHeader(b []byte) (net.IP, int, int, error) {
	if len(b) < udpHeaderMinLen {
		return nil, 0, 0, fmt.Errorf("short datagram %d", len(b))
	}
	atyp := b[3]
	off := 4
	var ip net.IP
	switch atyp {
	case socksAtypIPv4:
		ip = net.IP(b[off : off+net.IPv4len])
		off += net.IPv4len
	case socksAtypIPv6:
		ip = net.IP(b[off : off+net.IPv6len])
		off += net.IPv6len
	default:
		return nil, 0, 0, fmt.Errorf("unsupported atyp %#x", atyp)
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2

	return ip, port, off, nil
}

func startUDPSocksServer(t *testing.T, upstreamURL string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := &SocksServer{
		listener: ln,
		rotate:   func(key string) (string, error) { return upstreamURL, nil },
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	return ln.Addr().String()
}

func TestSocksServerUDPAssociateRoundTrip(t *testing.T) {
	echoAddr := startUDPEchoServer(t)
	upstreamURL := startFakeSocksUDPUpstream(t)
	socksAddr := startUDPSocksServer(t, upstreamURL)

	ctrl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := ctrl.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, sel); err != nil {
		t.Fatal(err)
	}
	if sel[1] != socksMethodNoAuth {
		t.Fatalf("method selection: want NO_AUTH, got %#x", sel[1])
	}

	if _, err := ctrl.Write([]byte{socksVersion5, socksCmdUDPAssociate, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}

	relayAddr := readUDPBindReply(t, ctrl)

	client, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("mubeng-udp-associate")
	datagram := []byte{0x00, 0x00, 0x00, socksAtypIPv4}
	datagram = append(datagram, echoAddr.IP.To4()...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(echoAddr.Port))
	datagram = append(datagram, payload...)

	if _, err := client.Write(datagram); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 64*1024)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("read udp response: %s", err)
	}

	_, _, payloadOff, err := parseSocksUDPHeader(resp[:n])
	if err != nil {
		t.Fatalf("parse response header: %s", err)
	}
	if got := resp[payloadOff:n]; !bytes.Equal(got, payload) {
		t.Fatalf("udp echo mismatch: want %q, got %q", payload, got)
	}
}

func TestSocksServerUDPAssociateRejectsNonSocks5Upstream(t *testing.T) {
	socksAddr := startUDPSocksServer(t, "http://127.0.0.1:1")

	ctrl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := ctrl.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, sel); err != nil {
		t.Fatal(err)
	}

	if _, err := ctrl.Write([]byte{socksVersion5, socksCmdUDPAssociate, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}

	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != socksReplyGeneralErr {
		t.Fatalf("reply: want general-error (%#x), got %#x", socksReplyGeneralErr, rep[1])
	}
}

func readUDPBindReply(t *testing.T, conn net.Conn) *net.UDPAddr {
	t.Helper()

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != socksReplySuccess {
		t.Fatalf("udp associate reply: want success, got %#x", head[1])
	}

	var ip net.IP
	switch head[3] {
	case socksAtypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		ip = net.IP(buf)
	case socksAtypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		ip = net.IP(buf)
	default:
		t.Fatalf("unexpected bind atyp %#x", head[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		t.Fatal(err)
	}

	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(portBuf))}
}
