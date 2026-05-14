package server

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/mbndr/logo"
	"github.com/mubeng/mubeng/common"
	"github.com/mubeng/mubeng/internal/proxygateway"
	"github.com/mubeng/mubeng/internal/proxymanager"
)

func init() {
	rec := logo.NewReceiver(os.Stderr, "")
	rec.Level = logo.WARN
	log = logo.NewLogger(rec)
}

func startCapturingOrigin(t *testing.T) (addr string, received <-chan []byte, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					select {
					case ch <- bytes.Clone(buf[:n]):
					default:
					}
				}
				_, _ = c.Write([]byte("ok"))
			}(c)
		}
	}()
	return ln.Addr().String(), ch, func() { _ = ln.Close() }
}

func startCONNECTProxy(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				br := bufio.NewReader(client)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer upstream.Close()
				_, _ = client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); _, _ = io.Copy(upstream, br) }()
				go func() { defer wg.Done(); _, _ = io.Copy(client, upstream) }()
				wg.Wait()
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startTestMubeng(t *testing.T, upstreams []string, noMITM bool) (addr string, stop func()) {
	t.Helper()
	f, err := os.CreateTemp("", "mubeng-proxies-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range upstreams {
		if _, err := f.WriteString(u + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	pm, err := proxymanager.New(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	proxy := &Proxy{
		HTTPProxy: goproxy.NewProxyHttpServer(),
		Options: &common.Options{
			ProxyManager: pm,
			Method:       "sequent",
			Rotate:       1,
			MaxRetries:   1,
			MaxErrors:    3,
			MaxRedirects: 5,
			Timeout:      10 * time.Second,
			NoMITM:       noMITM,
		},
		Gateways: make(map[string]*proxygateway.ProxyGateway),
	}
	proxy.HTTPProxy.OnRequest().DoFunc(proxy.onRequest)
	proxy.HTTPProxy.OnRequest().HandleConnectFunc(proxy.onConnect)
	proxy.HTTPProxy.ConnectDialWithReq = proxy.connectDial

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	srv := &http.Server{Handler: proxy.HTTPProxy}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() {
		_ = srv.Close()
		os.Remove(f.Name())
	}
}

// With --no-mitm, CONNECT bytes must reach the origin verbatim.
func TestConnectTunnelByteIdentity_NoMITM(t *testing.T) {
	originAddr, recvCh, stopOrigin := startCapturingOrigin(t)
	defer stopOrigin()
	upstreamAddr, stopUpstream := startCONNECTProxy(t)
	defer stopUpstream()
	mubengAddr, stopMubeng := startTestMubeng(t, []string{"http://" + upstreamAddr}, true)
	defer stopMubeng()

	conn, err := net.DialTimeout("tcp", mubengAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CONNECT " + originAddr + " HTTP/1.1\r\nHost: " + originAddr + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	marker := []byte("MUBENG-NO-MITM-MARKER-\x00\x01\x02\xff")
	if _, err := conn.Write(marker); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-recvCh:
		if !bytes.Equal(got, marker) {
			t.Errorf("origin saw bytes %q, want %q", got, marker)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin received nothing within 5s")
	}
}

// Default (MITM on) must intercept HTTPS — non-TLS bytes are rejected by goproxy
// during the TLS handshake, never reaching the origin.
func TestConnectMITM_Default(t *testing.T) {
	originAddr, recvCh, stopOrigin := startCapturingOrigin(t)
	defer stopOrigin()
	upstreamAddr, stopUpstream := startCONNECTProxy(t)
	defer stopUpstream()
	mubengAddr, stopMubeng := startTestMubeng(t, []string{"http://" + upstreamAddr}, false)
	defer stopMubeng()

	conn, err := net.DialTimeout("tcp", mubengAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CONNECT " + originAddr + " HTTP/1.1\r\nHost: " + originAddr + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	marker := []byte("MUBENG-MARKER-NOT-TLS")
	_, _ = conn.Write(marker)

	select {
	case got := <-recvCh:
		t.Fatalf("origin should not see bytes under MITM; got %q", got)
	case <-time.After(1500 * time.Millisecond):
	}
}

func TestDialUpstreamUnknownScheme(t *testing.T) {
	p := &Proxy{
		HTTPProxy: goproxy.NewProxyHttpServer(),
		Options:   &common.Options{},
	}
	if _, err := p.dialUpstream("gopher://localhost:70", "tcp", "example.com:443"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}
