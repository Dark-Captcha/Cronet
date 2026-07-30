# Patches

Changes applied to a Chromium checkout before `libcronet.so` is built.
`scripts/build_native.sh` applies them in order and refuses to build if one will not apply.
They target Chromium 150.0.7871.100.

| Patch                             | Tree                        | What it adds                              |
| --------------------------------- | --------------------------- | ----------------------------------------- |
| `0001-tls-profile-net.patch`      | `chromium/src`              | The `//net` half of `TlsProfile`          |
| `0002-tls-profile-boringssl.patch` | `third_party/boringssl/src` | The BoringSSL half of `TlsProfile`        |

## Planned: HTTP/3 through a SOCKS5 proxy

Not written yet.
This section records what was established about the problem so the work can be picked up without re-deriving it; every file and line below was read from Chromium 150.0.7871.100 source, not recalled.

### The problem

A request through any proxy arrives over HTTP/2, never HTTP/3, however many warm-up requests are made and whatever `quic_hints` says.
Measured across three residential proxy vendors, with a SOCKS5 relay logging every command: six `CONNECT` (0x01) commands and **zero** `UDP ASSOCIATE` (0x03).
Chromium never attempts QUIC through the proxy at all, so this is not a missing feature at the proxy — it is a decision on the client side.

Nothing reports it.
`Response.http_version` reads `"h2"` and no error is raised, which is why `require_http3=True` exists in the Python layer: it turns the silence into a failure for callers whose traffic is only worth sending over HTTP/3.

### Where Chromium decides

`net/http/http_stream_factory_job.cc`, in `Job::DoInitConnectionImplQuic()`:

```cpp
ProxyChain proxy_chain = proxy_info_.proxy_chain();
if (!proxy_chain.is_direct()) {
  // We only support proxying QUIC over QUIC. While MASQUE defines mechanisms
  // to carry QUIC traffic over non-QUIC proxies, the performance of these
  // mechanisms would be worse than simply using H/1 or H/2 to reach the
  // destination. The error for an invalid condition should not be user
  // visible, because the non-alternative Job should be resumed.
  if (proxy_chain.AnyProxy([](const ProxyServer& s) { return !s.is_quic(); })) {
    return ERR_NO_SUPPORTED_PROXIES;
  }
}
```

Three things follow from that comment, and they shape the whole design:

Chromium already carries QUIC over a **QUIC** proxy — `is_quic()` chains are supported end to end, so the machinery for proxied QUIC exists and only the SOCKS5 case is excluded.
The exclusion is a **performance judgement**, not an impossibility.
And the failure is deliberately invisible, because the non-alternative job is expected to resume — which is precisely the silent downgrade observed.

### What it would take

Two integration points and one new class.

**1. Relax the gate** — `net/http/http_stream_factory_job.cc`, the block above.
Allow a chain whose proxies are SOCKS5 through to the QUIC path instead of returning `ERR_NO_SUPPORTED_PROXIES`.

**2. Build the socket through the proxy** — `net/quic/quic_session_pool.cc`, `QuicSessionPool::CreateSocket()`:

```cpp
auto socket = client_socket_factory_->CreateDatagramClientSocket(
    DatagramSocket::DEFAULT_BIND, net_log, source);
```

Every QUIC socket comes from here, and `ConnectAndConfigureSocket()` takes a plain `DatagramClientSocket*`, so a SOCKS5-aware implementation of that interface slots in without touching the QUIC session itself.

**3. A new `DatagramClientSocket`** carrying RFC 1928 UDP relaying:

- open a TCP control connection to the proxy, greet, authenticate, then send `UDP ASSOCIATE` (0x03),
- read `BND.ADDR` and `BND.PORT` from the reply — the relay endpoint datagrams go to,
- hold the TCP connection open for the lifetime of the association, because the proxy drops the relay when it closes,
- on write, prefix each datagram with the SOCKS5 UDP header (`RSV RSV FRAG ATYP DST.ADDR DST.PORT` — ten bytes for IPv4), and strip it again on read.

`net/socket/socks5_client_socket.{h,cc}` is a `StreamSocket` with the command hardcoded to `kTunnelCommand`, so it is a reference for the handshake rather than something to extend.

### Authentication comes with it

The same file's class comment reads *"Currently no SOCKSv5 authentication is supported"*, and the client offers only `AUTH_NONE` — confirmed by `tests/test_proxy.py`, where a proxy demanding RFC 1929 credentials is a strict `xfail`.

Residential proxies require authentication, and their usernames carry the country and session selection, so RFC 1929 is not optional for this to be useful.
It is worth doing on its own: it needs no UDP and no enterprise proxy tier, and it unblocks authenticated residential proxies over HTTP/2 today.

Four files, and the first is the surprising one.

**`net/base/proxy_string_util.cc`**, in `ProxySchemeHostAndPortToProxyServer()`:

```cpp
if (username_component.is_valid() || password_component.is_valid() ||
    hostname_component.is_empty()) {
  return ProxyServer();
}
```

Chromium rejects any proxy URI that carries credentials, for every scheme.
That is why `proxy="socks5://user:password@host:1080"` fails with `ERR_NO_SUPPORTED_PROXIES` (-336) before a connection is attempted: the rule parses to an invalid `ProxyServer`, so the chain has no usable proxy in it.
The parser already splits the userinfo out — it just throws it away.

**`net/base/proxy_server.{h,cc}`** — carry the username and password that the parser currently discards.

**`net/socket/socks_connect_job.{h,cc}`** — `SOCKSSocketParams` reaches the construction site at `socks_connect_job.cc:179`, which today passes three arguments and would pass the credentials as a fourth.

**`net/socket/socks5_client_socket.{h,cc}`** — offer method `0x02` alongside `0x00` in `kSOCKS5GreetWriteData`, accept it in `DoGreetReadComplete()` where anything but `0x00` is currently an error, and add four states for the RFC 1929 sub-negotiation between the greeting and the existing handshake.

`scripts/probe_socks5_udp.py` implements that same sub-negotiation in Python and is verified against the suite's SOCKS5 server, so it is a working reference for the byte layout.

### Order of work

Authentication first, since it stands alone and is far smaller.
Then prove a given vendor actually relays QUIC datagrams, using a plain SOCKS5 UDP client outside Chromium — a rebuild is expensive and a vendor whose UDP support is off, or gated behind a tier, would waste all of it.
Only then the datagram socket and the gate.
