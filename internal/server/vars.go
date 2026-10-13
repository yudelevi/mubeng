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
