package server

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mbndr/logo"
	"h12.io/socks"
)

func init() {
	log = logo.NewLogger(logo.NewReceiver(io.Discard, ""))
}

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	return ln
}

func startSocksServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := &SocksServer{
		listener: ln,
		dial: func(network, addr, key string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 5*time.Second)
		},
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

func TestSocksServerConnectRoundTrip(t *testing.T) {
	echo := startEchoServer(t)
	socksAddr := startSocksServer(t)

	_, echoPort, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"ipv4":   echo.Addr().String(),                    // ATYP = IPv4
		"domain": net.JoinHostPort("localhost", echoPort), // ATYP = domain name
	}

	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			dialer := socks.Dial(fmt.Sprintf("socks5://%s?timeout=5s", socksAddr))
			conn, err := dialer("tcp", target)
			if err != nil {
				t.Fatalf("socks dial to %s: %s", target, err)
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

			want := []byte("mubeng-socks5")
			if _, err := conn.Write(want); err != nil {
				t.Fatalf("write: %s", err)
			}

			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read: %s", err)
			}
			if string(got) != string(want) {
				t.Fatalf("echo mismatch: want %q, got %q", want, got)
			}
		})
	}
}

// startRecordingSocksServer runs a SocksServer whose dial closure records the
// threaded session key, so tests can assert what negotiate() extracted.
func startRecordingSocksServer(t *testing.T) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	keyCh := make(chan string, 1)
	s := &SocksServer{
		listener: ln,
		dial: func(network, addr, key string) (net.Conn, error) {
			select {
			case keyCh <- key:
			default:
			}
			return net.DialTimeout(network, addr, 5*time.Second)
		},
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

	return ln.Addr().String(), keyCh
}

func connectViaIPv4(t *testing.T, conn net.Conn, target net.Addr) {
	t.Helper()

	host, port, _ := net.SplitHostPort(target.String())
	ip := net.ParseIP(host).To4()
	p, _ := strconv.Atoi(port)
	req := []byte{socksVersion5, socksCmdConnect, 0x00, socksAtypIPv4}
	req = append(req, ip...)
	req = append(req, byte(p>>8), byte(p))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != socksReplySuccess {
		t.Fatalf("connect reply: got %#x", rep[1])
	}
}

func TestSocksServerUserPassKeyThreaded(t *testing.T) {
	echo := startEchoServer(t)
	socksAddr, keyCh := startRecordingSocksServer(t)

	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting offering ONLY username/password (0x02) — what cloakbrowser sends
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodUserPass}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatal(err)
	}
	if sel[1] != socksMethodUserPass {
		t.Fatalf("method: want 0x02, got %#x", sel[1])
	}

	// RFC1929 auth: VER=1, ULEN, "alice", PLEN, "pw"
	user, pass := []byte("alice"), []byte("pw")
	auth := []byte{socksAuthVersion, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatal(err)
	}
	if authResp[0] != socksAuthVersion || authResp[1] != socksAuthSuccess {
		t.Fatalf("auth reply: got %#x %#x", authResp[0], authResp[1])
	}

	connectViaIPv4(t, conn, echo.Addr())

	select {
	case got := <-keyCh:
		if got != "alice" {
			t.Fatalf("threaded key = %q, want alice", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial closure never called")
	}
}

// Backward-compat: a no-auth (0x00) client — no session — threads an empty key,
// so downstream selection stays on the rotate path exactly as before.
func TestSocksServerNoAuthEmptyKey(t *testing.T) {
	echo := startEchoServer(t)
	socksAddr, keyCh := startRecordingSocksServer(t)

	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatal(err)
	}
	if sel[1] != socksMethodNoAuth {
		t.Fatalf("method: want 0x00, got %#x", sel[1])
	}

	connectViaIPv4(t, conn, echo.Addr())

	select {
	case got := <-keyCh:
		if got != "" {
			t.Fatalf("no-auth threaded key = %q, want empty", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial closure never called")
	}
}

func TestSocksServerRejectsBind(t *testing.T) {
	socksAddr := startSocksServer(t)

	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting: VER=5, 1 method, NO_AUTH
	if _, err := conn.Write([]byte{socksVersion5, 0x01, socksMethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatal(err)
	}
	if sel[1] != socksMethodNoAuth {
		t.Fatalf("method selection: want NO_AUTH, got %#x", sel[1])
	}

	// request BIND (0x02) for 127.0.0.1:80 — must be rejected as cmd-not-supported
	if _, err := conn.Write([]byte{socksVersion5, 0x02, 0x00, socksAtypIPv4, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != socksReplyCmdNoSupp {
		t.Fatalf("reply: want command-not-supported (%#x), got %#x", socksReplyCmdNoSupp, rep[1])
	}
}
