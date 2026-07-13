package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/mubeng/mubeng/common"
)

const (
	socksVersion5 = 0x05

	socksMethodNoAuth   = 0x00
	socksMethodUserPass = 0x02
	socksMethodNoAccept = 0xFF

	socksAuthVersion = 0x01
	socksAuthSuccess = 0x00
	socksAuthFailure = 0x01

	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03
	socksAtypIPv4        = 0x01
	socksAtypDomainName  = 0x03
	socksAtypIPv6        = 0x04
	socksReplySuccess    = 0x00
	socksReplyGeneralErr = 0x01
	socksReplyCmdNoSupp  = 0x07

	socksHandshakeTimeout = 30 * time.Second
)

// SocksServer is a minimal SOCKS5 (RFC 1928) proxy. Each accepted connection is
// tunneled through an upstream proxy rotated from its own pool
// (Options.SocksProxyManager), reusing the same upstream-dial path as the HTTP
// listener so SOCKS v4(A)/v5 and HTTP/S upstreams are all supported. The
// CONNECT and UDP ASSOCIATE commands are handled; BIND is rejected. UDP
// ASSOCIATE only works through socks5 upstreams that themselves support it.
type SocksServer struct {
	opt      *common.Options
	listener net.Listener
	dial     func(network, addr, key string) (net.Conn, error)
	// rotate returns the upstream proxy URL for a UDP association given the
	// session key. It is separate from dial because UDP ASSOCIATE needs the raw
	// socks5:// URL to run its own handshake (h12.io/socks has no UDP support).
	rotate func(key string) (string, error)
	// drop clears a sticky pin (nil when sticky is disabled or in tests).
	drop func(key string)
}

// NewSocksServer builds a SOCKS5 listener that shares the handler's upstream
// dial logic and rotation/error options.
func NewSocksServer(opt *common.Options, handler *Proxy) *SocksServer {
	return &SocksServer{
		opt:  opt,
		dial: func(network, addr, key string) (net.Conn, error) { return handler.dialViaSocksPool(network, addr, key) },
		rotate: func(key string) (string, error) {
			if opt.SocksSticky != nil && key != "" {
				return opt.SocksSticky.Get(key)
			}
			return opt.SocksProxyManager.Rotate(opt.SocksMethod)
		},
		drop: func(key string) {
			if opt.SocksSticky != nil {
				opt.SocksSticky.Drop(key)
			}
		},
	}
}

// ListenAndServe binds Options.SocksAddress and serves until Close is called.
func (s *SocksServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.opt.SocksAddress)
	if err != nil {
		return err
	}
	s.listener = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Errorf("SOCKS5 accept error: %s", err)
			continue
		}

		go s.handle(conn)
	}
}

// Close stops accepting new connections.
func (s *SocksServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}

	return nil
}

func (s *SocksServer) handle(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(socksHandshakeTimeout))

	cmd, target, sessionKey, err := s.negotiate(conn)
	if err != nil {
		log.Debugf("%s SOCKS5 handshake: %s", conn.RemoteAddr(), err)
		return
	}

	if cmd == socksCmdUDPAssociate {
		s.handleUDPAssociate(conn, sessionKey)
		return
	}

	upstream, err := s.dial("tcp", target, sessionKey)
	if err != nil {
		log.Errorf("%s SOCKS5 %s: %s", conn.RemoteAddr(), target, err)
		_ = reply(conn, socksReplyGeneralErr)
		return
	}
	defer upstream.Close()

	if err := reply(conn, socksReplySuccess); err != nil {
		return
	}

	// relay phase: drop the handshake deadline, copy bytes both ways
	_ = conn.SetDeadline(time.Time{})
	relay(conn, upstream)
}

// negotiate runs SOCKS5 method selection and reads the request, returning the
// command and the requested "host:port" target. Domain names are forwarded
// unresolved so the upstream proxy performs DNS resolution at its exit. For UDP
// ASSOCIATE the returned target is the client's advertised DST (often 0.0.0.0:0)
// and is ignored by the caller.
func (s *SocksServer) negotiate(conn net.Conn) (byte, string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", "", err
	}
	if header[0] != socksVersion5 {
		return 0, "", "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, "", "", err
	}

	// Prefer username/password (0x02) when offered so the username can serve as the
	// sticky session key (for clients that CAN authenticate); otherwise fall back to
	// no-auth (0x00). Chromium can't send SOCKS5 credentials at all, so it always lands
	// on 0x00 and is keyed on the CONNECT destination host below. 0x02 is accepted only
	// when sticky is enabled, so a sticky-off listener rejects credential-only clients.
	stickyOn := s.opt != nil && s.opt.Sticky
	selected := byte(socksMethodNoAccept)
	switch {
	case stickyOn && containsByte(methods, socksMethodUserPass):
		selected = socksMethodUserPass
	case containsByte(methods, socksMethodNoAuth):
		selected = socksMethodNoAuth
	}
	if selected == socksMethodNoAccept {
		_, _ = conn.Write([]byte{socksVersion5, socksMethodNoAccept})
		return 0, "", "", errors.New("client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socksVersion5, selected}); err != nil {
		return 0, "", "", err
	}

	var sessionKey string
	if selected == socksMethodUserPass {
		user, err := readUserPassAuth(conn)
		if err != nil {
			return 0, "", "", err
		}
		sessionKey = user
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return 0, "", "", err
	}
	if req[0] != socksVersion5 {
		return 0, "", "", fmt.Errorf("unsupported SOCKS version %d", req[0])
	}
	if req[1] != socksCmdConnect && req[1] != socksCmdUDPAssociate {
		_ = reply(conn, socksReplyCmdNoSupp)
		return 0, "", "", fmt.Errorf("unsupported command %d", req[1])
	}

	host, err := readHost(conn, req[3])
	if err != nil {
		_ = reply(conn, socksReplyGeneralErr)
		return 0, "", "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, "", "", err
	}

	// A client that presents no username (Chromium can't send SOCKS5 credentials) still
	// needs a stable exit IP per site to clear Cloudflare. When sticky is on, key the pin
	// on the CONNECT destination host: every connection to a host — main document, XHRs,
	// the challenge POST — then shares one upstream IP so cf_clearance stays valid, while
	// distinct hosts fan out across the pool. UDP ASSOCIATE is excluded; its DST is the
	// client's advertised address, not a site.
	if sessionKey == "" && stickyOn && req[1] == socksCmdConnect {
		sessionKey = host
	}

	return req[1], net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))), sessionKey, nil
}

// readUserPassAuth runs the RFC1929 username/password sub-negotiation, returning
// the username (the session key). The password is read but not validated — it is
// only a routing tag; the upstream pool is IP-whitelisted. A success reply is
// always sent so any credential is accepted.
func readUserPassAuth(conn net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != socksAuthVersion {
		_, _ = conn.Write([]byte{socksAuthVersion, socksAuthFailure})
		return "", fmt.Errorf("unsupported auth version %d", head[0])
	}

	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return "", err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return "", err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return "", err
	}

	if _, err := conn.Write([]byte{socksAuthVersion, socksAuthSuccess}); err != nil {
		return "", err
	}

	return string(user), nil
}

func readHost(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypDomainName:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

// reply writes a SOCKS5 reply with a zero BND.ADDR/BND.PORT, which clients
// ignore for CONNECT.
func reply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{socksVersion5, status, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)

	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()

	// returning closes both conns via the caller's defers, unblocking the
	// other copy goroutine; the buffered channel keeps it from leaking.
	<-done
}

func containsByte(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}

	return false
}

// dialViaSocksPool rotates the SOCKS5 upstream pool and dials addr through it,
// retrying on failure per the shared rotate/remove-on-error options.
func (p *Proxy) dialViaSocksPool(network, addr, key string) (net.Conn, error) {
	attempts := p.Options.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	sticky := p.Options.SocksSticky != nil && key != ""

	var lastErr error
	for i := 0; i < attempts; i++ {
		var proxyAddr string
		var err error
		if sticky {
			proxyAddr, err = p.Options.SocksSticky.Get(key)
		} else {
			proxyAddr, err = p.Options.SocksProxyManager.Rotate(p.Options.SocksMethod)
		}
		if err != nil {
			return nil, err
		}

		conn, err := p.dialUpstream(proxyAddr, network, addr)
		if err == nil {
			log.Debugf("SOCKS5 CONNECT %s via %s", addr, proxyAddr)
			return conn, nil
		}
		lastErr = err
		log.Debugf("SOCKS5 CONNECT %s via %s failed: %s", addr, proxyAddr, err)

		if sticky {
			p.Options.SocksSticky.Drop(key)
		}
		if p.Options.RemoveOnErr {
			if rmErr := p.Options.SocksProxyManager.RemoveProxy(proxyAddr); rmErr != nil {
				log.Debug(rmErr)
			}
		}
		if !p.Options.RotateOnErr {
			break
		}
		if p.Options.MaxErrors >= 0 && i+1 >= p.Options.MaxErrors {
			break
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("connect to %s failed: exhausted upstream attempts", addr)
	}

	return nil, lastErr
}
