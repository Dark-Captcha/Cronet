# Patches

Changes applied to a Chromium checkout before `libcronet.so` is built.
`scripts/build_native.sh` applies them in order and refuses to build if one will not apply.
They target Chromium 150.0.7871.100.

| Patch                              | Tree                        | What it adds                                     |
| ---------------------------------- | --------------------------- | ------------------------------------------------ |
| `0001-tls-profile-net.patch`       | `chromium/src`              | The `//net` half of `TlsProfile`                 |
| `0002-tls-profile-boringssl.patch` | `third_party/boringssl/src` | The BoringSSL half of `TlsProfile`               |
| `0003-socks5-auth.patch`           | `chromium/src`              | SOCKS5 username/password authentication          |
| `0004-socks5-udp-quic.patch`       | `chromium/src`              | HTTP/3 through a SOCKS5 proxy's UDP relay        |

None of them changes what a destination server sees.
The TLS fingerprint, the HTTP/2 and HTTP/3 framing and the header order are Chromium's own, whether a request goes direct or through a proxy — measured, not assumed: the same JA4 and the same pinned JA3 come back either way.
What the last two change is which proxies can be reached at all, and that is a conversation between the client and the proxy that the destination never sees.

## 0003: SOCKS5 authentication

Upstream offers only the "no authentication" method, and its proxy URI parser discards any userinfo outright, so `socks5://user:password@host:1080` fails with `ERR_NO_SUPPORTED_PROXIES` (-336) while the rules are still being parsed.
Residential proxies require authentication and carry country and session selection in the username, so this made them unusable.

Four files:

- **`net/base/proxy_string_util.cc`** keeps the credentials the parser already splits out, for `socks5` only — an HTTP proxy authenticates through its own 407 exchange, so accepting userinfo there would look like it worked and quietly do nothing.
- **`net/base/proxy_server.{h,cc}`** carries them. The special members move out of line, because chromium-style requires that of a class with non-trivial members.
- **`net/socket/socks_connect_job.{h,cc}`** passes them to the socket.
- **`net/socket/socks5_client_socket.{h,cc}`** offers method `0x02` beside `0x00`, and runs the RFC 1929 subnegotiation between the greeting and the handshake.

## 0004: HTTP/3 through a SOCKS5 proxy

Upstream carries QUIC over a QUIC proxy and refuses every other kind, in two places, so a proxied request always lands on HTTP/2.
`net/socket/socks5_udp_client_socket.{h,cc}` adds the missing transport: a `DatagramClientSocket` that resolves the proxy, opens a TCP control connection, greets, authenticates, sends `UDP ASSOCIATE` (RFC 1928, 0x03), and then relays datagrams through the address the proxy names, wrapping each one in the request header of RFC 1928 section 7.
The control connection stays open for the association's lifetime, because a proxy drops the relay when it closes.

`IsSocks5UdpProxyChain()` lives beside that socket so the rule has one home; four call sites ask it rather than repeating the test:

- **`net/http/http_stream_factory_job.cc`** — two separate gates return `ERR_NO_SUPPORTED_PROXIES` for a non-QUIC proxy chain, and the earlier one runs first. Relaxing only the later one changes nothing, which is worth knowing before debugging it.
- **`net/quic/quic_session_pool.cc`** — `CreateSocket()` wraps the datagram socket, and job selection sends a SOCKS5 chain down the direct path. `ProxyJob` builds a QUIC session *to* the proxy and tunnels inside it, which is what a QUIC proxy needs and not what a relay does.
- **`net/quic/quic_session_attempt.cc`** — an association needs a TCP connection and several round trips before its first datagram, so it always takes the asynchronous branch whatever `kAsyncQuicSession` says.
- **`net/quic/quic_chromium_client_session.cc`** — the network-migration probe sockets get the same treatment.

### What it needs from the proxy

The proxy has to answer `UDP ASSOCIATE` and then actually relay.
`scripts/probe_socks5_udp.py` asks both questions without involving Chromium, and is worth running before anything else.

A relay is usually IPv4-only, and an IPv6 destination is then dropped without a reply — the request simply falls back to HTTP/2. That is the failure most likely to be mistaken for the patch not working.
