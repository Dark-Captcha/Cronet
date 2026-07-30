# cronet

Chromium's network stack — the one inside Chrome — as a Python HTTP client.
Requests go out over Chrome's own TLS, HTTP/2 and HTTP/3 implementations, its connection pooling and its DNS machinery, so what a server sees is the browser's traffic because it is the browser's code, not an imitation of it.
The package is `ctypes` over one bundled shared library and has zero runtime dependencies.

> Perishable facts in this file — the Chromium version, quoted outputs, wire behaviour, benchmark numbers — were verified by running them against the bundled build (Chromium 150.0.7871.100, Python 3.14.2 free-threaded and 3.14.6 standard, Linux x86-64) on 2026-07-31.

```python
from cronet import Session

with Session() as session:
    response = session.get("https://example.com")
    print(response.status_code, response.http_version)
# 200 h2
```

## Contents

- [Why this exists](#why-this-exists)
- [Requirements](#requirements)
- [Install](#install)
- [Limitations](#limitations)
- [Sessions and requests](#sessions-and-requests)
- [Header order](#header-order)
- [Redirects](#redirects)
- [Cookies](#cookies)
- [Proxies](#proxies)
- [HTTP/3](#http3)
- [TLS fingerprints](#tls-fingerprints)
- [Threads and asyncio](#threads-and-asyncio)
- [Responses](#responses)
- [Errors](#errors)
- [Recording a NetLog](#recording-a-netlog)
- [How it is put together](#how-it-is-put-together)
- [Performance](#performance)
- [Building the native library](#building-the-native-library)
- [Licensing](#licensing)

## Why this exists

An ordinary HTTP client speaks HTTP correctly, but nothing about its connection resembles a browser: its TLS handshake, its HTTP/2 fingerprint and its header ordering are all its own.
This library is Chromium's actual `//net` stack behind a small C ABI, so those details are Chrome's by construction.
Two consequences, both measured rather than assumed: the JA3 fingerprint varies per connection exactly as Chrome's does (and can be pinned — see [TLS fingerprints](#tls-fingerprints)), and HTTP/3 is a real QUIC transport, not an advertisement of one.

## Requirements

- Linux, x86-64. Nothing else is shipped.
- Python 3.14 or newer, on either the standard or the free-threaded build.
- The system libraries the bundled `libcronet.so` links directly: GLib (`libglib-2.0`, `libgobject-2.0`, `libgio-2.0`) and NSS (`libnss3`, `libnssutil3`, `libnspr4`).
  The remainder of its link list — `libc`, `libm`, `libdl`, `libpthread`, `libgcc_s` — ships with the base system.
  Desktop distributions have all of these already; a slim container image needs `libglib2.0-0` and `libnss3` (Debian, Ubuntu) or `glib2` and `nss` (Arch, Fedora).
- A glibc system.
  The library asks for no symbol newer than GLIBC 2.18, so the C library is rarely what stands in the way.
  The C++ runtime never is: libstdc++ is linked statically, which is why it is absent from the list above.

## Install

The repository ships the built `libcronet.so` inside the package, so a clone is enough:

```bash
pip install .
```

The built wheel contains the shared library and the LICENSE file; no compiler and no Chromium checkout are involved in installing.
It is tagged `py3-none-linux_x86_64`, so pip on any other platform declines it rather than installing a library it cannot load.
That tag is deliberately not one of the `manylinux` ones: manylinux promises a wheel that leans on nothing outside its own allowlist, and this one needs the system's GLib and NSS.
The wheel therefore installs from a file, a URL or a release asset, but is not in a state to be uploaded to PyPI.

`msgspec` is used for JSON encoding and decoding when it happens to be installed, and the standard library's `json` otherwise; the two produce the same values, so it is an accelerator, not a dependency.

## Limitations

Stated here, before the tour, because discovering these later is worse.

- **Linux x86-64 only.** The bundled library is built for that one platform.
- **Request bodies are held whole.** A body is passed to the native side as one buffer, so uploading a file larger than memory is not possible; responses have no such limit, because they stream.
- **The proxy is a session setting, not a request option.** Changing proxies means opening another session.
- **SOCKS proxies do not authenticate.** Chromium's SOCKS client implements no username/password handshake (RFC 1929), so `socks4://` and `socks5://` work only with proxies that accept unauthenticated connections.
  `proxy_username` and `proxy_password` apply to HTTP and HTTPS proxies only.
- **A streamed response carries no metrics and no history.** Cronet collects timings during teardown, and a streamed request lets Chromium follow redirects itself; read the response whole when either matters.

## Sessions and requests

A session owns one native engine, and that engine owns the connection pools, the DNS cache and the TLS session cache its requests share.
Making a second request to the same host through one session is what makes it cheap, so a session is worth keeping rather than making per request.

```python
from cronet import Session

with Session(headers={"accept": "application/json"}, timeout=10.0) as session:
    session.get("https://example.com/one")
    session.get("https://example.com/two")  # reuses the connection
```

`Session` provides `request`, `get`, `post`, `put`, `patch`, `delete`, `head` and `options`, plus `stream` for a response read as it arrives.
Every one of them takes the same options:

| Option          | Meaning                                                                          |
| --------------- | -------------------------------------------------------------------------------- |
| `headers`       | Sent after the session's own, replacing a name the session already set, in place |
| `query`         | Added to the URL's query string                                                  |
| `body`          | Raw `bytes` or `str`                                                             |
| `form`          | Fields, sent url-encoded                                                         |
| `files`         | Files, sent as `multipart/form-data`; may be combined with `form`                |
| `json`          | Any serialisable value, sent as `application/json`                               |
| `basic_auth`    | `(username, password)`, sent as an Authorization header                          |
| `bearer_auth`   | A token, sent as `Authorization: Bearer …`                                       |
| `timeout`       | Seconds for this request; `None` for no limit                                    |
| `max_redirects` | Redirects to follow for this request                                             |
| `priority`      | One of `Priority.THROTTLED` … `Priority.HIGHEST`; the default is `MEDIUM`        |
| `disable_cache` | Bypass the session cache for this request                                        |

An option the library does not know is an error rather than something quietly dropped, because `allow_redirects=False` from `requests` or `verify=False` from `httpx` would otherwise vanish and the request would go out with settings nobody asked for:

```python
session.get("https://example.com", allow_redirects=False)
# TypeError: unknown request option: 'allow_redirects' — did you mean 'max_redirects'?
```

Bodies are given in exactly one of `body`, `form` or `json`; `files` is the one that may travel beside `form`, since that is what a browser sends for a form carrying an upload.
The multipart boundary is generated in Chrome's own shape, and a quote or newline inside a field name or filename is percent-encoded so it cannot write headers of its own.

```python
session.post(
    "https://example.com/upload",
    form={"caption": "a photo"},
    files={"photo": ("cat.png", image_bytes, "image/png")},
)
```

A file is given as bytes or text alone, as `(filename, content)`, or as `(filename, content, media_type)`.
Where no media type is given it is guessed from the filename, falling back to `application/octet-stream`.

For a response too large to hold, `stream` hands back the response once its headers arrive and leaves the body on the network:

```python
with session.stream("GET", "https://example.com/big.iso") as response:
    for piece in response.iter_bytes():
        sink.write(piece)
```

Reading is what lets the transfer continue, so a slow consumer slows the transfer down rather than filling memory.

The session itself takes the settings its requests share.
`proxy`, `cookies`, `quic_hints` and `tls` have sections of their own below; the rest are these:

| Setting                    | Meaning                                                                      |
| -------------------------- | ---------------------------------------------------------------------------- |
| `headers`                  | Sent with every request, in this order                                       |
| `user_agent`               | Defaults to a Chrome User-Agent for the bundled Chromium                     |
| `accept_language`          | Sent when a request sets no Accept-Language of its own                       |
| `http2`, `http3`           | Whether HTTP/2 and HTTP/3 may be negotiated; both are on                     |
| `brotli`                   | Whether brotli is advertised in Accept-Encoding                              |
| `cache`, `cache_size`      | `"off"`, `"memory"` or `"disk"`, and a size in bytes; 0 lets Chromium choose |
| `storage_path`             | Directory for an on-disk cache, which `cache="disk"` requires                |
| `timeout`, `max_redirects` | The defaults each request inherits                                           |
| `experimental_options`     | Cronet experimental options, passed through as JSON                          |

Chromium always emits a User-Agent, so `user_agent=""` sends an empty header rather than none at all.
`version()` returns the Chromium version the bundled library was built from, and `default_user_agent()` the string derived from it.

## Header order

The order headers reach the wire in is a fingerprint, as much as their values are, and reproducing Chrome's is most of the point of this library.
Headers are sent in the order given, repeats included, and a name the session already set keeps the session's position while taking the request's value.

Some headers are the network stack's rather than the caller's, and passing one is refused:

```python
session.get(url, headers={"accept-encoding": "gzip, deflate, br"})
# ValueError: 'accept-encoding' was set on a request, but Chromium sets it
# itself — the session's brotli= setting decides this. ...
```

The refused names are `accept-encoding`, `accept-language`, `host`, `connection` and `content-length`.
Chromium accepts all of them silently, so without this the request would simply stop looking like a browser's and nothing would say so.
Use `Session(accept_language=...)` for the language, `Session(brotli=...)` for the encoding, and let Chromium derive the rest.

This matters most for `Referer`.
Chromium strips it from the caller's list and re-appends it — `net/url_request/url_request_http_job.cc` does this so that nothing can override a referrer policy by setting the header — which places it after everything else the caller sent.
In Chrome that is exactly the right position, because the headers that follow it are added by the network stack rather than by the caller.
So put `referer` last in your list, leave the stack's own headers alone, and the order comes out as Chrome sends it:

```python
with Session(accept_language="en-US,en;q=0.9") as session:
    session.get(
        url,
        headers=[
            ("sec-ch-ua", '"Chromium";v="150", "Not?A_Brand";v="24"'),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", '"Linux"'),
            ("upgrade-insecure-requests", "1"),
            ("user-agent", default_user_agent()),
            ("accept", "text/html,application/xhtml+xml"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
            ("referer", "https://example.com/"),
        ],
    )
```

That arrives as the ten above, then `accept-encoding` and `accept-language` from the stack.
`tests/test_header_order.py` pins this, so a Chromium upgrade that moves a header fails the suite rather than quietly changing what every request looks like.

## Redirects

Redirects are followed automatically, up to `max_redirects` — twenty by default, and settable per session or per request.
Chromium follows them on its own thread, which is why `Response.history` is empty unless a cookie jar is in use.

Two rules are Chromium's own, and this library applies the same ones when it walks a chain itself.
A 303 becomes a GET unless the request was a HEAD, and a 301 or 302 becomes a GET only for a POST; anything else keeps its method, and only a method change drops the body.

Credentials do not follow a redirect to a different origin.
`basic_auth`, `bearer_auth`, and any `authorization` or `cookie` header set by hand are dropped the moment the scheme, host or port changes, because carrying them onward would hand them to a host the caller never named.

## Cookies

Cronet runs with its own cookie store switched off, so a jar lives on the Python side, built on the standard library's `http.cookiejar` — which already knows the domain, path, expiry and `Secure` rules that make cookie handling correct rather than merely plausible.

```python
with Session(cookies=True) as session:
    session.get("https://example.com/login")
    session.get("https://example.com/account")  # sends what was set
```

Pass a `CookieJar` instead of `True` to share one between sessions, or to inspect it:

```python
from cronet import CookieJar, Session

jar = CookieJar()
with Session(cookies=jar) as session:
    session.get("https://example.com/login")
print(len(jar), jar.header_for("https://example.com/"))
```

A jar changes how redirects are followed.
With one in use the chain is walked a hop at a time, so a cookie set part-way along is stored before the next request goes out — and each hop then appears in `Response.history`.
A jar is safe to share between threads and between sessions.

## Proxies

The proxy is set on the session, in Chromium's own rule syntax:

```python
Session(proxy="http://127.0.0.1:8080")
Session(proxy="socks5://127.0.0.1:1080")
Session(proxy="http=http://a:8080;https=socks5://b:1080")
```

Schemes are `http`, `https`, `socks4`, `socks5` and `direct`.
`proxy_bypass` names hosts to reach directly, as in `"localhost;*.internal"`.
Chromium never proxies loopback addresses unless that list contains `<-loopback>`, which is worth knowing when testing against a proxy on the same machine.

`proxy_username` and `proxy_password` are offered pre-emptively as Basic authentication, and apply to HTTP and HTTPS proxies only.
Chromium's SOCKS client does not implement RFC 1929, so a SOCKS proxy demanding a password cannot be used at all.

## HTTP/3

HTTP/3 is on by default, but a host is only reached over QUIC once an earlier response has advertised it — that is how Chrome behaves too.
`quic_hints` names hosts already known to speak it, so the first request goes over QUIC without the round trip that discovers it:

```python
with Session(quic_hints=["cloudflare-quic.com"]) as session:
    response = session.get("https://cloudflare-quic.com/")
    print(response.http_version)
# h3
```

A hint is a bare name, or a name with its port as `("example.com", 443)`.
Pass `http3=False` to switch QUIC off, and `http2=False` to force HTTP/1.1.

### HTTP/3 does not survive a proxy

A request through a proxy arrives over HTTP/2, never HTTP/3, whatever `quic_hints` says and however many requests have gone before it.
Chromium carries QUIC over a QUIC proxy only, and declines it for every other kind — it never sends the SOCKS5 `UDP ASSOCIATE` that a UDP relay would need, so the proxy is not what is refusing.
The reasoning, and what changing it would take, is in [`patches/README.md`](patches/README.md).

Nothing announces this.
`Response.http_version` reads `"h2"`, no error is raised, and Chromium's own comment says the failure "should not be user visible" because the HTTP/2 attempt is expected to take over.
For traffic that is only worth sending over HTTP/3, that silence is the danger, so it can be turned into a failure:

```python
from cronet import ProtocolDowngraded, Session

with Session(require_http3=True, quic_hints=["cloudflare-quic.com"]) as session:
    response = session.get("https://cloudflare-quic.com/")  # h3, or it raises
```

A response that arrives over anything else raises `ProtocolDowngraded`, which carries the response on `.response` for a caller that would rather inspect than fail.
A session that cannot reach HTTP/3 at all is refused when it is opened rather than once per request — `require_http3=True` beside a `proxy`, or beside `http3=False`, raises `ValueError` there and then.

Whether a given proxy could ever carry HTTP/3 is a question about the proxy, and `scripts/probe_socks5_udp.py` answers it without involving Chromium:

```bash
scripts/probe_socks5_udp.py socks5://user:password@proxy.example:1080
```

It greets the proxy, authenticates, asks for a UDP relay, and sends a real DNS query through it — so a pass means datagrams genuinely flow, not merely that the proxy claimed they would.

## TLS fingerprints

Chrome does two things that make its handshake deliberately unrepeatable: it shuffles the ClientHello extensions on every connection, and it injects GREASE values in several places.
This library inherits both, so by default its JA3 fingerprint differs from connection to connection exactly as Chrome's does — four fresh sessions produce four different hashes.

`DETERMINISTIC` switches off just those two sources of variation, leaving every other Chromium parameter alone:

```python
from cronet import DETERMINISTIC, Session

with Session(tls=DETERMINISTIC) as session:
    session.get("https://example.com")
```

Four fresh sessions then produce one hash, repeatedly.
JA4 is unchanged either way, because it sorts the extensions before hashing them and so never saw the shuffle to begin with.

`TlsProfile` pins individual parts for anything more specific.
Every field is optional and one left alone keeps Chromium's behaviour, so a profile that sets one thing changes one thing:

| Field                  | Pins                                                        |
| ---------------------- | ----------------------------------------------------------- |
| `cipher_suites`        | The offered suites, in this order                           |
| `extension_order`      | Extension types in the order they must appear               |
| `supported_groups`     | The supported_groups extension, in order                    |
| `key_share_groups`     | Which groups carry a key share                              |
| `signature_algorithms` | The signature_algorithms extension, in order                |
| `alpn`                 | Protocols offered, from `h2`, `http/1.1`, `h3`              |
| `min_version`          | `"1.2"` or `"1.3"`                                          |
| `max_version`          | `"1.2"` or `"1.3"`                                          |
| `grease`               | `False` removes every GREASE value; `True` forces them on   |
| `permute_extensions`   | `False` makes the extension order deterministic             |

Values are IANA code points, as they appear on the wire.
Setting `extension_order` implies `permute_extensions=False`, since an explicit order is meaningless while the shuffle is on.
Extensions 21 and 41 cannot be positioned — BoringSSL always emits padding last, and the TLS specification requires `pre_shared_key` last — so naming either one is rejected rather than silently ignored.

## Threads and asyncio

Both session types are safe to share between threads, and neither keeps state whose integrity depends on the GIL.
A blocking request releases the GIL while it waits, so requests made from different threads genuinely overlap.

```python
from concurrent.futures import ThreadPoolExecutor

with Session() as session, ThreadPoolExecutor(16) as pool:
    responses = list(pool.map(session.get, urls))
```

`AsyncSession` is the same surface with `await` in front of it, and `aclose` instead of `close`:

```python
import asyncio
from cronet import AsyncSession


async def main():
    async with AsyncSession() as session:
        responses = await asyncio.gather(*(session.get(url) for url in urls))


asyncio.run(main())
```

Waiting happens on a descriptor the native library makes readable when a call progresses, so no thread is parked per request and the event loop is never blocked on the network.
Cancelling the awaiting task cancels the request itself.

## Responses

A response arrives with its body already decompressed: Chromium undoes gzip, deflate, brotli and zstd before Python sees it.

| Attribute        | Meaning                                                                    |
| ---------------- | -------------------------------------------------------------------------- |
| `status_code`    | The HTTP status                                                            |
| `reason`         | The status text, which is empty on HTTP/2 and HTTP/3 — they carry none     |
| `headers`        | A `Headers` mapping, in the order the server sent them                     |
| `content`        | The body, decompressed                                                     |
| `text`           | `content` decoded with `encoding`                                          |
| `encoding`       | The charset named by Content-Type, or utf-8                                |
| `url`            | The final URL, after any redirects                                         |
| `http_version`   | `"http/1.1"`, `"h2"` or `"h3"` once ALPN has run; `"unknown"` when it has not, as on plaintext HTTP |
| `redirect_count` | How many redirects were followed                                           |
| `from_cache`     | Whether the session's cache answered this                                  |
| `proxy`          | Host and port of the proxy used, or `"direct"`                             |
| `metrics`        | Per-phase timings                                                          |
| `history`        | Each earlier hop, oldest first, when a cookie jar made the walk hop-by-hop |
| `ok`             | Whether the status is 2xx                                                  |
| `elapsed`        | Seconds from the request starting to its last byte                         |

`json()` parses the body, `raise_for_status()` returns the response or raises on 4xx and 5xx, and `iter_bytes()` walks the body in pieces whether or not it was streamed.

`Headers` keeps wire order and matches names without regard to case.
A name sent more than once joins with `", "` on lookup, and `get_list` returns the values separately.

`metrics` carries the timings Cronet reports, in microseconds since the epoch: `request_start_us`, `dns_start_us`, `dns_end_us`, `connect_start_us`, `connect_end_us`, `ssl_start_us`, `ssl_end_us`, `send_start_us`, `send_end_us`, `response_start_us` and `request_end_us`, plus `sent_bytes`, `received_bytes` and `socket_reused`.
A phase the request never reached — no `dns_start` on a reused socket, no `ssl_start` on plaintext — reads `NO_TIME`.
`total_us` is the whole request, or `NO_TIME` when either end went unrecorded.

## Errors

Everything raised derives from `CronetError`, and the split is by what a caller would do about it.

```text
CronetError
├── LibraryError      the library could not be loaded, or refused a configuration
├── SessionClosed     the session was used after it was closed
├── HTTPStatusError   raise_for_status() met a 4xx or 5xx; carries .response
└── RequestError      the request produced no response; carries .net_error and .url
    ├── ConnectionFailed
    ├── Timeout
    ├── Cancelled
    ├── TooManyRedirects
    ├── ProxyFailed
    └── CertificateError
```

Every `RequestError` carries `net_error`, the Chromium network error code that produced it, negative and documented in Chromium's `net_error_list.h` — `-105` for `ERR_NAME_NOT_RESOLVED`, `-201` for a bad certificate, `-7` for a timeout.
That code is the most precise thing there is to look up, which is why it is kept rather than flattened into a message.

One code is this library's own rather than Chromium's: `-31`, for a redirect chain that ran past its limit.
The rest are Chromium's unchanged, so looking one up means looking it up in Chromium.

```python
from cronet import CertificateError, RequestError, Session

with Session() as session:
    try:
        response = session.get("https://expired.badssl.com/")
    except CertificateError as error:
        print("bad certificate:", error.net_error)  # -201
    except RequestError as error:
        print("no response:", error.net_error)
```

Note that a 404 is not an error: it is a response, and asking for one is `raise_for_status()`.

## Recording a NetLog

A NetLog is Chromium's own trace format, readable in the [NetLog viewer](https://netlog-viewer.appspot.com/).
It is the fastest way to find out what the stack actually did with a request.

```python
with Session() as session:
    session.start_net_log("trace.json")
    session.get("https://example.com")
    session.stop_net_log()
```

`log_all=True` adds socket bytes and cookies, which is far more detail and includes credentials — so a log taken that way should be treated as a secret.
Only one log may run at a time per session, and the file is flushed on `stop_net_log`.

## How it is put together

Five layers, each knowing only the one beneath it:

```text
session.py, request.py, response.py   the surface written against
_bridge.py                            marshalling and handle lifetimes
_binding.py                           loading the library, checking its ABI
_abi.py                               the ctypes declarations, generated
libcronet.so                          Chromium's network stack
```

`_bridge` is the only module that converts between Python values and C memory; everything above it is ordinary Python that happens to be fast.
`_abi` is generated from `native/cronet.h` by `scripts/generate_binding.py`, never written by hand, because a second hand-kept copy of an ABI is one that eventually disagrees with the first — and a struct read at the wrong offset corrupts silently instead of failing.
A test fails if the checked-in `_abi.py` is not what the generator produces from the current header.

The ABI version is checked at import.
A library built from a different header fails immediately and says so, rather than reading every field at the wrong offset.

## Performance

Measured on 2026-07-31, against a loopback HTTP/1.1 server returning a 1 KB JSON body, 300 requests per round, median of five rounds.
A raw socket reusing one connection reaches 40,837 requests a second against that server, so the numbers below are bounded by the client rather than by the server.

On the standard build of Python 3.14.6, beside `httpx` 0.28.1:

| Case              | cronet | httpx |
| ----------------- | ------ | ----- |
| sequential        |  7,670 | 3,721 |
| 16 threads        |  6,009 | 2,209 |
| asyncio           |  7,241 |   919 |

Concurrency does not add throughput here, and on the standard build it subtracts some: the work is bound by CPU rather than by waiting, so more threads only add contention for one GIL.
That changes on the free-threaded build, where the same threads run in parallel:

| Threads | standard (GIL) | free-threaded |
| ------- | -------------- | ------------- |
| 1       |          7,639 |         7,539 |
| 4       |          6,379 |        16,359 |
| 16      |          5,120 |        18,285 |
| 64      |          4,123 |        16,170 |

Against a server that sleeps 20 ms before answering — the shape of a real network — both builds behave identically, rising from 49 requests a second on one thread to 288 on sixteen, because there the bottleneck is waiting and the GIL is released for the whole of it.

The lesson worth carrying: threads buy latency-hiding on either build, and buy throughput only on the free-threaded one.

## Building the native library

Only needed to rebuild `libcronet.so`; installing the package needs none of this.

It requires a Chromium checkout and depot_tools, and it is a large build.

```bash
export CHROMIUM_SRC=/path/to/chromium/src
export DEPOT_TOOLS=/path/to/depot_tools   # defaults to ~/depot_tools
scripts/build_native.sh
```

The script applies the two patches in `patches/`, copies `native/` into the checkout, builds with GN and ninja, strips the result into `src/cronet/libcronet.so`, and regenerates `src/cronet/_abi.py` from `native/cronet.h`.
Both of those files are committed, so a rebuild shows up as a diff rather than as a step somebody has to remember.
Setting `CRONET_LIBRARY` to a path makes the package load that library instead of the bundled one, which is how a build is tried before it is installed.

No file belonging to Chromium is modified: the sources are copied into a directory Chromium does not otherwise use, and GN is pointed straight at it with `--root-target`.
The patches add the opt-in TLS profile support that `TlsProfile` drives — without them the library still builds and works, but a profile would be silently ignored, so they are applied rather than optional.
Applying is idempotent, since a patch already in the tree reverse-applies cleanly.

The patches target Chromium 150.0.7871.100; the script warns when the checkout is a different version, and stops if a patch will not apply.

## Licensing

This package is BSD 3-Clause, and the full text is in [LICENSE](LICENSE).

`src/cronet/libcronet.so` is compiled from The Chromium Project, which is itself distributed under a BSD 3-Clause licence and contains further third-party components under their own terms.
Chromium's licence is reproduced in full in [LICENSE](LICENSE), below this project's own.
The complete set of third-party licences travels with the Chromium source, at <https://chromium.googlesource.com/chromium/src/+/main/LICENSE> and in that tree's `third_party` directories.
