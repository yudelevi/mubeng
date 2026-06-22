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

	socksMethodNoAuth    = 0x00
	socksMethodNoAccept  = 0xFF
	socksCmdConnect      = 0x01
	socksAtypIPv4        = 0x01
	socksAtypDomainName  = 0x03
	socksAtypIPv6        = 0x04
	socksReplySuccess    = 0x00
	socksReplyGeneralErr = 0x01
	socksReplyCmdNoSupp  = 0x07

	socksHandshakeTimeout = 30 * time.Second
)

// SocksServer is a minimal SOCKS5 (RFC 1928) CONNECT proxy. Each accepted
// connection is tunneled through an upstream proxy rotated from its own pool
// (Options.SocksProxyManager), reusing the same upstream-dial path as the HTTP
// listener so SOCKS v4(A)/v5 and HTTP/S upstreams are all supported. Only the
// CONNECT command is handled; BIND and UDP ASSOCIATE are rejected.
type SocksServer struct {
	opt      *common.Options
	listener net.Listener
	dial     func(network, addr string) (net.Conn, error)
}

// NewSocksServer builds a SOCKS5 listener that shares the handler's upstream
// dial logic and rotation/error options.
func NewSocksServer(opt *common.Options, handler *Proxy) *SocksServer {
	return &SocksServer{
		opt:  opt,
		dial: func(network, addr string) (net.Conn, error) { return handler.dialViaSocksPool(network, addr) },
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

	target, err := s.negotiate(conn)
	if err != nil {
		log.Debugf("%s SOCKS5 handshake: %s", conn.RemoteAddr(), err)
		return
	}

	upstream, err := s.dial("tcp", target)
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

// negotiate runs SOCKS5 method selection and reads the CONNECT request,
// returning the requested "host:port" target. Domain names are forwarded
// unresolved so the upstream proxy performs DNS resolution at its exit.
func (s *SocksServer) negotiate(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socksVersion5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if !containsByte(methods, socksMethodNoAuth) {
		_, _ = conn.Write([]byte{socksVersion5, socksMethodNoAccept})
		return "", errors.New("client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socksVersion5, socksMethodNoAuth}); err != nil {
		return "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[0] != socksVersion5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", req[0])
	}
	if req[1] != socksCmdConnect {
		_ = reply(conn, socksReplyCmdNoSupp)
		return "", fmt.Errorf("unsupported command %d", req[1])
	}

	host, err := readHost(conn, req[3])
	if err != nil {
		_ = reply(conn, socksReplyGeneralErr)
		return "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}

	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))), nil
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
func (p *Proxy) dialViaSocksPool(network, addr string) (net.Conn, error) {
	attempts := p.Options.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		proxyAddr, err := p.Options.SocksProxyManager.Rotate(p.Options.SocksMethod)
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
