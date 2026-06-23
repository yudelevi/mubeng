package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync/atomic"
	"time"
)

const (
	// udpRelayBufSize bounds a single relayed datagram. QUIC initials fit well
	// under this; oversized datagrams are dropped rather than truncated.
	udpRelayBufSize = 64 * 1024

	// udpAssociateTimeout caps the raw SOCKS5 UDP ASSOCIATE handshake with the
	// upstream proxy.
	udpAssociateTimeout = 15 * time.Second

	// udpIdleTimeout tears down an association whose UDP sockets have seen no
	// traffic for this long, backstopping the control-connection lifetime tie.
	udpIdleTimeout = 60 * time.Second
)

// handleUDPAssociate services a SOCKS5 UDP ASSOCIATE request. It picks one
// rotated upstream socks5 proxy, performs a raw UDP ASSOCIATE handshake with
// it, opens a local UDP relay socket for the client, and pumps datagrams both
// ways for the lifetime of the client's TCP control connection (clientCtrl).
//
// Any failure before the client reply is sent results in a clean general-error
// reply so the client (e.g. Chrome's QUIC) falls back to TCP instead of hanging.
func (s *SocksServer) handleUDPAssociate(clientCtrl net.Conn) {
	bindIP := listenIP(clientCtrl.LocalAddr())

	clientRelay, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		log.Errorf("%s SOCKS5 UDP: open client relay: %s", clientCtrl.RemoteAddr(), err)
		_ = reply(clientCtrl, socksReplyGeneralErr)
		return
	}
	defer clientRelay.Close()

	upstreamCtrl, upstreamRelayAddr, err := s.dialUpstreamUDPAssociate()
	if err != nil {
		log.Debugf("%s SOCKS5 UDP associate: %s", clientCtrl.RemoteAddr(), err)
		_ = reply(clientCtrl, socksReplyGeneralErr)
		return
	}
	defer upstreamCtrl.Close()

	upstreamRelay, err := net.DialUDP("udp", nil, upstreamRelayAddr)
	if err != nil {
		log.Debugf("%s SOCKS5 UDP dial upstream relay %s: %s", clientCtrl.RemoteAddr(), upstreamRelayAddr, err)
		_ = reply(clientCtrl, socksReplyGeneralErr)
		return
	}
	defer upstreamRelay.Close()

	if err := replyUDPBind(clientCtrl, clientRelay.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	_ = clientCtrl.SetDeadline(time.Time{})

	done := make(chan struct{})
	go relayUDP(clientRelay, upstreamRelay, done)

	// The association lives as long as the control connection. Block reading
	// it; any read result (EOF, error, or stray byte) ends the association.
	buf := make([]byte, 1)
	_, _ = io.ReadFull(clientCtrl, buf)
	close(done)
}

// relayUDP pumps datagrams between the client and the upstream proxy's UDP
// relay. The SOCKS5 UDP request header (RSV FRAG ATYP DST.ADDR DST.PORT) is
// identical on both legs, so datagrams are forwarded verbatim. The client's
// source address is learned from its first datagram; replies are sent back
// there. Closed when done is closed (or either socket errors).
func relayUDP(clientRelay, upstreamRelay *net.UDPConn, done <-chan struct{}) {
	go func() {
		<-done
		_ = clientRelay.SetReadDeadline(time.Now())
		_ = upstreamRelay.SetReadDeadline(time.Now())
	}()

	var clientAddr atomic.Pointer[net.UDPAddr]

	go func() {
		buf := make([]byte, udpRelayBufSize)
		for {
			_ = upstreamRelay.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := upstreamRelay.Read(buf)
			if err != nil {
				return
			}
			dst := clientAddr.Load()
			if dst == nil {
				continue
			}
			if _, err := clientRelay.WriteToUDP(buf[:n], dst); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, udpRelayBufSize)
	for {
		_ = clientRelay.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, addr, err := clientRelay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		clientAddr.Store(addr)

		// Drop fragmented datagrams (FRAG != 0); we do not reassemble.
		if n < udpHeaderMinLen || buf[2] != 0x00 {
			continue
		}
		if _, err := upstreamRelay.Write(buf[:n]); err != nil {
			return
		}
	}
}

// udpHeaderMinLen is the smallest valid SOCKS5 UDP request header: RSV(2)
// FRAG(1) ATYP(1) + IPv4 addr(4) + port(2).
const udpHeaderMinLen = 2 + 1 + 1 + net.IPv4len + 2

// dialUpstreamUDPAssociate rotates an upstream socks5 proxy and performs a raw
// SOCKS5 UDP ASSOCIATE handshake with it, returning the still-open TCP control
// connection (which must stay open for the association's lifetime) and the
// upstream's UDP relay address to send datagrams to. Only socks5 upstreams with
// no-auth (IP-whitelisted) are supported, matching the Proxyrack residential
// pool.
func (s *SocksServer) dialUpstreamUDPAssociate() (net.Conn, *net.UDPAddr, error) {
	proxyAddr, err := s.rotate()
	if err != nil {
		return nil, nil, err
	}

	u, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse proxy %q: %w", proxyAddr, err)
	}
	if u.Scheme != "socks5" {
		return nil, nil, fmt.Errorf("UDP associate needs a socks5 upstream, got %q", u.Scheme)
	}

	ctrl, err := net.DialTimeout("tcp", u.Host, udpAssociateTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream %s: %w", u.Host, err)
	}

	relayAddr, err := socksUDPAssociate(ctrl, u.Host)
	if err != nil {
		ctrl.Close()
		return nil, nil, err
	}

	log.Debugf("SOCKS5 UDP associate via %s relay %s", proxyAddr, relayAddr)

	return ctrl, relayAddr, nil
}

// socksUDPAssociate runs the SOCKS5 no-auth greeting and UDP ASSOCIATE command
// on an already-connected upstream control connection, returning the upstream's
// UDP relay address. If the upstream advertises a wildcard BND.ADDR (0.0.0.0 or
// ::), datagrams are sent to the proxy host itself (proxyHost) per RFC 1928.
func socksUDPAssociate(ctrl net.Conn, proxyHost string) (*net.UDPAddr, error) {
	_ = ctrl.SetDeadline(time.Now().Add(udpAssociateTimeout))
	defer ctrl.SetDeadline(time.Time{})

	if _, err := ctrl.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		return nil, fmt.Errorf("greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, sel); err != nil {
		return nil, fmt.Errorf("method selection: %w", err)
	}
	if sel[0] != socksVersion5 || sel[1] != socksMethodNoAuth {
		return nil, fmt.Errorf("upstream rejected no-auth (got %#x %#x)", sel[0], sel[1])
	}

	// UDP ASSOCIATE with a wildcard DST.ADDR/DST.PORT (0.0.0.0:0): we do not
	// know the client's UDP source yet, so let the upstream relay accept any.
	if _, err := ctrl.Write([]byte{socksVersion5, socksCmdUDPAssociate, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("associate request: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		return nil, fmt.Errorf("associate reply header: %w", err)
	}
	if head[0] != socksVersion5 {
		return nil, fmt.Errorf("unexpected reply version %#x", head[0])
	}
	if head[1] != socksReplySuccess {
		return nil, fmt.Errorf("upstream UDP associate failed (rep %#x)", head[1])
	}

	host, err := readHost(ctrl, head[3])
	if err != nil {
		return nil, fmt.Errorf("associate reply addr: %w", err)
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, portBuf); err != nil {
		return nil, fmt.Errorf("associate reply port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		proxyIPHost, _, splitErr := net.SplitHostPort(proxyHost)
		if splitErr != nil {
			proxyIPHost = proxyHost
		}
		host = proxyIPHost
	}

	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, fmt.Errorf("resolve upstream relay %s:%d: %w", host, port, err)
	}

	return relayAddr, nil
}

// replyUDPBind sends a SOCKS5 success reply carrying mubeng's UDP relay address
// (BND.ADDR/BND.PORT) so the client knows where to send its datagrams.
func replyUDPBind(conn net.Conn, relay *net.UDPAddr) error {
	ip := relay.IP
	atyp := byte(socksAtypIPv4)
	addr := ip.To4()
	if addr == nil {
		atyp = socksAtypIPv6
		addr = ip.To16()
	}

	out := make([]byte, 0, 6+len(addr))
	out = append(out, socksVersion5, socksReplySuccess, 0x00, atyp)
	out = append(out, addr...)
	out = binary.BigEndian.AppendUint16(out, uint16(relay.Port))

	_, err := conn.Write(out)
	return err
}

// listenIP picks the local IP a UDP relay should bind to, derived from the
// control connection's local address. A wildcard or non-IP address falls back
// to loopback so the BND.ADDR sent to the client is always dialable.
func listenIP(local net.Addr) net.IP {
	if tcp, ok := local.(*net.TCPAddr); ok && tcp.IP != nil && !tcp.IP.IsUnspecified() {
		return tcp.IP
	}

	return net.IPv4(127, 0, 0, 1)
}
