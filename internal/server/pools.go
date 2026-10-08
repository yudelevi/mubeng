package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/fsnotify/fsnotify"
	"github.com/henvic/httpretty"
	"github.com/mbndr/logo"
	"github.com/mubeng/mubeng/common"
	"github.com/mubeng/mubeng/internal/metrics"
	"github.com/mubeng/mubeng/internal/proxygateway"
	"github.com/mubeng/mubeng/internal/proxymanager"
)

// RunPools serves independent listeners in one process. All sockets are bound
// before serving, so a failed bind cannot leave a partially started deployment.
func RunPools(opt *common.Options) error {
	receiver := logo.NewReceiver(os.Stderr, "")
	receiver.Color = true
	receiver.Level = logo.DEBUG
	recs := []*logo.Receiver{receiver}
	if opt.Output != "" {
		file, err := logo.Open(opt.Output)
		if err != nil {
			return err
		}
		defer file.Close()
		recs = append(recs, logo.NewReceiver(file, ""))
	}
	log = logo.NewLogger(recs...)
	dump = &httpretty.Logger{RequestHeader: true, ResponseHeader: true, Colors: true}
	type runningPool struct {
		handler *Proxy
		http    *http.Server
		socks   *SocksServer
	}
	var pools []runningPool
	var listeners []net.Listener
	var watchers []*fsnotify.Watcher
	var stickies []*proxymanager.Sticky
	var watchWG sync.WaitGroup
	var metricServer *metrics.Server
	metricsEnabled = opt.Metrics != ""
	updateSizes := func() {
		if !metricsEnabled {
			return
		}
		total := 0
		for _, child := range opt.Pools {
			count := child.ProxyManager.Count()
			total += count
			metrics.PoolSize.WithLabelValues(child.PoolName).Set(float64(count))
		}
		metrics.ProxyPoolSize.Set(float64(total))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() {
		cancel()
		for _, w := range watchers {
			_ = w.Close()
		}
		watchWG.Wait()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if metricServer != nil {
			_ = metricServer.Shutdown(shutdown)
		}
		for _, pool := range pools {
			if pool.http != nil {
				_ = pool.http.Shutdown(shutdown)
			}
			pool.handler.mu.Lock()
			for _, gateway := range pool.handler.Gateways {
				_ = gateway.Close(shutdown)
			}
			pool.handler.mu.Unlock()
		}
		for _, sticky := range stickies {
			sticky.Close()
		}
	}()
	for _, child := range opt.Pools {
		child.OnPoolChange = updateSizes
		p := &Proxy{Options: child, HTTPProxy: goproxy.NewProxyHttpServer(), Gateways: make(map[string]*proxygateway.ProxyGateway)}
		p.HTTPProxy.AllowHTTP2 = true
		p.HTTPProxy.OnRequest().DoFunc(p.onRequest)
		p.HTTPProxy.OnRequest().HandleConnectFunc(p.onConnect)
		p.HTTPProxy.OnResponse().DoFunc(p.onResponse)
		p.HTTPProxy.NonproxyHandler = http.HandlerFunc(nonProxy)
		p.HTTPProxy.ConnectDialWithReq = p.connectDial
		address := child.Address
		pool := runningPool{handler: p}
		if child.Sticky {
			sticky := proxymanager.NewSticky(child.ProxyManager, child.Method, child.StickyTTL)
			stickies = append(stickies, sticky)
			if metricsEnabled {
				name := child.PoolName
				sticky.SetOnChange(func(n int) { metrics.StickyPins.WithLabelValues(name).Set(float64(n)) })
			}
			if address != "" {
				child.HTTPSticky = sticky
			} else {
				child.SocksSticky = sticky
			}
		}
		if address != "" {
			pool.http = &http.Server{Addr: address, Handler: p.HTTPProxy}
		} else {
			address = child.SocksAddress
			pool.socks = NewSocksServer(child, p)
		}
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("listen %s: %w", address, err)
		}
		listeners = append(listeners, ln)
		pools = append(pools, pool)
		if child.Watch {
			w, err := child.ProxyManager.Watch()
			if err != nil {
				return err
			}
			watchers = append(watchers, w)
			watchWG.Add(1)
			go func(child *common.Options, w *fsnotify.Watcher) {
				defer watchWG.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case event, ok := <-w.Events:
						if !ok {
							return
						}
						if filepath.Clean(event.Name) == filepath.Clean(child.File) && event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
							if err := child.ProxyManager.Reload(); err != nil {
								log.Errorf("Pool %s reload: %s", child.PoolName, err)
							} else {
								updateSizes()
							}
						}
					case err, ok := <-w.Errors:
						if !ok {
							return
						}
						log.Errorf("Pool watch: %s", err)
					}
				}
			}(child, w)
		}
	}
	var metricsListener net.Listener
	if metricsEnabled {
		var err error
		metricsListener, err = net.Listen("tcp", opt.Metrics)
		if err != nil {
			return fmt.Errorf("metrics listen: %w", err)
		}
		listeners = append(listeners, metricsListener)
		metricServer = metrics.NewServer(opt.Metrics)
		updateSizes()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	errs := make(chan error, len(pools)+1)
	if metricServer != nil {
		go func() { errs <- metricServer.Serve(metricsListener) }()
	}
	for i, pool := range pools {
		ln := listeners[i]
		log.Infof("Starting pool %s on %s (%d proxies)", pool.handler.Options.PoolName, ln.Addr(), pool.handler.Options.ProxyManager.Count())
		go func(pool runningPool, ln net.Listener) {
			var err error
			if pool.http != nil {
				err = pool.http.Serve(ln)
			} else {
				err = pool.socks.serve(ln)
			}
			errs <- err
		}(pool, ln)
	}
	select {
	case <-stop:
		return nil
	case err := <-errs:
		return err
	}
}
