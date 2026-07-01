# mubeng sticky sessions — design

**Date:** 2026-07-01
**Repo:** `~/dev/mubeng` (fork `github.com/yudelevi/mubeng`)
**Status:** ON HOLD — core assumption invalidated (see Blocker below); awaiting a
direction decision before revision.

## Blocker (found 2026-07-01, post-approval)

The design below keys SOCKS sessions off an RFC1929 username. **Chromium does not
support SOCKS5 proxy authentication** and never sends one. cloakbrowser (the
br_scrape engine) is plain Playwright **Chromium** pointed at
`socks5://127.0.0.1:3154`, so over that listener every browser context is an
indistinguishable no-auth connection from `127.0.0.1` — there is no channel to
carry a session id. The "SOCKS username = key" scheme cannot work for this stack.

The only channel Chromium populates is **HTTP proxy auth**. Viable path:

- Point cloakbrowser at the HTTP listener: `PROXY_URL=http://<session>:x@127.0.0.1:3153`
  (per browser context; username = the per-domain session id).
- mubeng runs `-no-mitm`, keys the pin off the CONNECT's `Proxy-Authorization`
  username (already available in `connectDial`).
- mubeng must issue a `407 Proxy-Authentication-Required` on an un-authed CONNECT
  to elicit the username (Chromium only sends creds after a 407; Playwright
  answers it). Small addition to `onConnect`.

Consequences: the SOCKS work (RFC1929 in `negotiate()`, UDP-ASSOCIATE pinning)
is **not needed** if cloakbrowser moves to `:3153` — sticky lives on the HTTP
listener only. And because Chromium only reveals the username after a 407, the
sticky HTTP port is effectively "strict" (auth-required), not fallback-rotate.

Directions on the table (pending user decision):
1. Move cloakbrowser to HTTP `:3153`, sticky-by-Proxy-Auth username, drop SOCKS
   sticky. (Recommended — only path that works with Chromium today.)
2. Keep SOCKS `:3154`, revisit a SOCKS5-auth-capable engine (Firefox/camoufox)
   — blocked on the firefox resolution-quality work that routes FF→chromium now.

The sections below reflect the pre-blocker (SOCKS-username) design and will be
revised once a direction is chosen.

---


## Problem

mubeng rotates the upstream exit IP per connection. Cloudflare binds its
challenge token and the `cf_clearance` cookie to one client IP, so a browser's
challenge → verify-POST → clearance → reload sequence egresses a different IP
each hop and CF never clears. Proven live: 3 back-to-back requests through the
SOCKS listener `:3154` exited 3 different ProxyRack IPs, and headed chromium
(br3) cannot pass any CF managed/Turnstile challenge.

ProxyRack already maps each upstream port to a stable residential IP (verified:
4 requests through `:10000` all exited `108.95.101.245`). So mubeng only needs
to **pin one existing pool entry per session** — no ProxyRack session-param
injection required.

## Goal

Add an opt-in **sticky mode**: connections that share a session key egress
through the same pinned upstream, for **both** listeners (HTTP `:3153`, SOCKS
`:3154`) and for SOCKS **UDP ASSOCIATE**. Default (flag absent) keeps today's
rotate-every-connection behavior, unchanged.

## Session key

- **SOCKS** — RFC1929 USERNAME/PASSWORD auth. `negotiate()` (in
  `internal/server/socks.go`) currently accepts only no-auth (`0x00`); it gains
  support for method `0x02`. The **username is the session key**. The password
  is accepted but not validated — the ProxyRack pool is IP-whitelisted and the
  credential is only a routing tag. No-auth `0x00` still works (used when sticky
  is off, or when a client sends no credentials).
- **HTTP** — username parsed from the `Proxy-Authorization: Basic` header.
  Available on plain-HTTP requests (`onRequest`) and on `-no-mitm` CONNECT
  tunnels (`connectDial` receives the `*http.Request`). **Limitation:** MITM'd
  HTTPS tunnels do not carry `Proxy-Authorization` on the inner decrypted
  request, so those requests fall back to rotation. Browser/CF scraping runs
  `-no-mitm`, so the CF path is fully covered. This limitation is documented,
  not worked around.

The username covers both listeners and is what Playwright sets as the
per-context proxy username (client side handled separately in br_scrape: a
per-domain session id pins one exit IP for that domain's whole render).

## `-A` interaction (decided)

Sticky treats the Proxy-Auth username as a routing key. `-A` compares the whole
`user:pass` to one fixed credential — the two conflict (a fixed `-A` username
would collapse every session onto one pin). **Decision: `-sticky` and `-A` are
mutually exclusive.** The runner validator returns a startup error if both are
set. The deployment does not use `-A`.

## Sticky store

New type `proxymanager.Sticky`, composing a `*ProxyManager`, its rotate method,
and a TTL:

```go
type Sticky struct {
    mgr      *ProxyManager
    method   string
    ttl      time.Duration
    mu       sync.Mutex
    pins     map[string]*stickyPin
    onChange func(n int) // optional; set by server when metrics enabled
    // janitor lifecycle fields (ticker/stop) as needed
}

type stickyPin struct {
    upstream string    // the concrete, already-evaluated URL from Rotate()
    expires  time.Time // refreshed on every access
}
```

Behavior:

- `Get(key string) (string, error)`:
  - empty key → plain `mgr.Rotate(method)`, no pin (preserves default behavior
    for clients that send no credentials);
  - live pin exists → refresh `expires = now + ttl`, return the stored
    `upstream` **verbatim**;
  - miss or expired → `mgr.Rotate(method)`, store the returned concrete URL,
    return it.
- `Drop(key string)`: delete the pin. Called on upstream dial failure so the
  next `Get` re-rotates and re-pins — this is **rotate-on-error per session**.
- Expiry: lazy check on `Get` **plus** a background janitor goroutine (ticker at
  the TTL interval) that sweeps expired pins, so the map does not grow unbounded
  on a long-lived daemon. `Close()` stops the janitor.
- `Len() int`: current pin count (for metrics).

**Why pin the evaluated URL:** `Rotate()` runs `helper.EvalFunc`, which expands
`{{uint32}}`-style templates. Pinning the concrete post-eval string and reusing
it verbatim is what makes the exit stable; re-evaluating on each reuse would
defeat stickiness.

**Two independent stores** — one wrapping `Options.ProxyManager` (HTTP pool),
one wrapping `Options.SocksProxyManager` (SOCKS pool) — because the pools are
separate. Held on `common.Options` (e.g. `HTTPSticky`, `SocksSticky
*proxymanager.Sticky`), constructed by the runner only when `-sticky` is set,
and `Close()`d on shutdown.

## Threading the key

- **SOCKS TCP:** `negotiate()` returns the username alongside cmd/target;
  `handle()` passes it into the dial path. `dialViaSocksPool` gains a session-key
  parameter: when sticky is enabled and the key is non-empty it selects the
  upstream via `SocksSticky.Get(key)` instead of `Rotate`; on dial failure it
  calls `Drop(key)` and retries, preserving `MaxRetries` / `RotateOnErr` /
  `RemoveOnErr` semantics.
- **SOCKS UDP:** `handleUDPAssociate` receives the key; `dialUpstreamUDPAssociate`
  uses `SocksSticky.Get(key)` in place of `s.rotate()`. On failure it calls
  `Drop(key)`. This pins QUIC/UDP egress to the same exit as the session's TCP
  flow.
- **HTTP:** proxy selection in `onRequest` and `connectDial` becomes key-aware —
  when sticky is enabled and a Proxy-Auth username is present, route through
  `HTTPSticky.Get(key)`; the error path drops the pin. When sticky is off, or no
  username is present (incl. MITM'd HTTPS), fall back to the existing
  `rotateProxy()` path unchanged.

## CLI

- `-sticky` (bool, default `false`) — enable sticky mode for both pools.
- `-sticky-ttl` (duration, default `10m`) — idle TTL; a pin is refreshed on each
  use and swept once idle past the TTL.

Follows the existing flag style (`-rotate-on-error`, `-max-errors`,
`-socks-method`). Validator: error if `-sticky` is set together with `-A`.

## Metrics

Add a `mubeng_sticky_pins` gauge with a `pool` label (`http` / `socks`),
following the existing `promauto` pattern in `internal/metrics/metrics.go`. To
avoid a `proxymanager → metrics` import dependency, the server sets each store's
`onChange` callback (when `metricsEnabled`) to update the gauge on pin
add/drop/sweep. Example series:

```
mubeng_sticky_pins{pool="socks"} 42
mubeng_sticky_pins{pool="http"}  7
```

## Preserved invariants

proxy-file watch/reload (pins hold concrete URLs; a reloaded-away upstream that
still dials keeps working, and if it fails, rotate-on-error re-pins),
`/metrics` pool size, UDP ASSOCIATE, and all `MaxRetries` / `MaxErrors` /
`RotateOnErr` / `RemoveOnErr` semantics.

## Testing

- **`proxymanager` (Sticky):** same key reuses one upstream across calls;
  distinct keys pin independently; `Drop` forces a re-rotate on next `Get`; a
  pin past TTL re-rotates; empty key bypasses pinning; `Len`/`onChange` track
  pin count.
- **`server` SOCKS:** `negotiate()` selects `0x02` and returns the username when
  offered, and still selects `0x00` when only no-auth is offered; two SOCKS
  connections carrying the same username dial through the same upstream (fake
  pool); `Drop` after a simulated failure re-rotates.
- **`server` HTTP:** Proxy-Authorization username extraction; two requests with
  the same username route through the same upstream; missing/MITM case falls
  back to rotation.
- **runner validator:** `-sticky` + `-A` errors.

## Out of scope

- ProxyRack session-param injection (not needed — ports are already stable IPs).
- Persisting pins across restarts (in-memory only; a restart re-pins on next
  connection, acceptable for CF's session lifetime).
- Sticky for MITM'd HTTPS (documented fallback to rotation).
