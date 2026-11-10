package server

import (
	"net/http"
	"sync"

	"github.com/henvic/httpretty"
	"github.com/mbndr/logo"
	"github.com/mubeng/mubeng/internal/metrics"
)

var (
	handler        *Proxy
	server         *http.Server
	socksServer    *SocksServer
	metricsServer  *metrics.Server
	metricsEnabled bool
	dump           *httpretty.Logger
	mime           = "text/plain"
	log            *logo.Logger

	mutex = sync.Mutex{}
)

// goproxyRefusalPrefix starts the error goproxy returns when an upstream proxy
// answers a CONNECT with a non-200 status.
const goproxyRefusalPrefix = "proxy refused connection"

// exitFailureTitles are proxyrack's 56x answers: the exit or the pool failed,
// not the target, so the pin must rotate rather than hold.
var exitFailureTitles = []string{
	"<title>561 Proxy Unreachable</title>",
	"<title>562 Proxy Not Found</title>",
	"<title>565 Proxy Handshake Failed</title>",
}
