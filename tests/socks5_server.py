"""A SOCKS5 proxy, just complete enough to test a client against.

It implements the CONNECT command over IPv4, hostnames and IPv6, with either no
authentication or the username/password exchange of RFC 1929. Anything else is
refused rather than guessed at, so a test failure points at the client rather
than at a half-implemented server.
"""

import contextlib
import socket
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERNAME_PASSWORD = 0x02
AUTH_UNACCEPTABLE = 0xFF
AUTH_SUBNEGOTIATION_VERSION = 0x01

COMMAND_CONNECT = 0x01
COMMAND_UDP_ASSOCIATE = 0x03
ADDRESS_IPV4 = 0x01
ADDRESS_DOMAIN = 0x03
ADDRESS_IPV6 = 0x04

REPLY_SUCCEEDED = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_COMMAND_NOT_SUPPORTED = 0x07


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(Socks5Server, self.server)
        try:
            if not self._greet(server):
                return
            target = self._read_request()
            if target is None:
                return
            self._connect_and_pump(target)
        except OSError, ValueError:
            # A client that hangs up mid-handshake is a case under test, not a
            # server fault; the assertions live in the test.
            pass

    def _receive_exactly(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = self.request.recv(count - len(data))
            if not chunk:
                raise OSError("the client hung up during the handshake")
            data += chunk
        return data

    def _greet(self, server: Socks5Server) -> bool:
        version, method_count = self._receive_exactly(2)
        if version != VERSION:
            raise ValueError(f"expected SOCKS5, got version {version}")
        offered = set(self._receive_exactly(method_count))
        server.offered_methods.append(offered)

        wanted = AUTH_USERNAME_PASSWORD if server.username else AUTH_NONE
        if wanted not in offered:
            self.request.sendall(bytes([VERSION, AUTH_UNACCEPTABLE]))
            return False
        self.request.sendall(bytes([VERSION, wanted]))
        return self._authenticate(server) if server.username else True

    def _authenticate(self, server: Socks5Server) -> bool:
        version = self._receive_exactly(1)[0]
        if version != AUTH_SUBNEGOTIATION_VERSION:
            raise ValueError(f"expected RFC 1929 version 1, got {version}")
        username = self._receive_exactly(self._receive_exactly(1)[0]).decode()
        password = self._receive_exactly(self._receive_exactly(1)[0]).decode()
        server.credentials_seen.append((username, password))

        accepted = username == server.username and password == server.password
        status = 0x00 if accepted else 0x01
        self.request.sendall(bytes([AUTH_SUBNEGOTIATION_VERSION, status]))
        return accepted

    def _read_request(self) -> tuple[str, int] | None:
        version, command, _reserved, address_type = self._receive_exactly(4)
        if version != VERSION:
            raise ValueError(f"expected SOCKS5, got version {version}")
        server = cast(Socks5Server, self.server)
        server.commands_seen.append(command)
        if command == COMMAND_UDP_ASSOCIATE:
            # The address the client names is where it expects to send from,
            # and a client that does not know yet sends zeroes; either way it
            # is read to keep the stream in step, then ignored.
            self._read_address(address_type)
            if not server.relay_udp:
                self._reply(REPLY_COMMAND_NOT_SUPPORTED)
                return None
            self._relay_datagrams()
            return None
        if command != COMMAND_CONNECT:
            self._reply(REPLY_COMMAND_NOT_SUPPORTED)
            return None

        if address_type == ADDRESS_IPV4:
            host = socket.inet_ntop(socket.AF_INET, self._receive_exactly(4))
        elif address_type == ADDRESS_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, self._receive_exactly(16))
        elif address_type == ADDRESS_DOMAIN:
            host = self._receive_exactly(self._receive_exactly(1)[0]).decode()
        else:
            self._reply(REPLY_GENERAL_FAILURE)
            return None

        port = int.from_bytes(self._receive_exactly(2), "big")
        return host, port

    def _read_address(self, address_type: int) -> tuple[str, int] | None:
        """The address and port of a request, whichever form it took."""
        if address_type == ADDRESS_IPV4:
            host = socket.inet_ntop(socket.AF_INET, self._receive_exactly(4))
        elif address_type == ADDRESS_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, self._receive_exactly(16))
        elif address_type == ADDRESS_DOMAIN:
            host = self._receive_exactly(self._receive_exactly(1)[0]).decode()
        else:
            return None
        return host, int.from_bytes(self._receive_exactly(2), "big")

    def _reply(self, code: int, bound: tuple[str, int] | None = None) -> None:
        host, port = bound or ("0.0.0.0", 0)
        self.request.sendall(
            bytes([VERSION, code, 0x00, ADDRESS_IPV4])
            + socket.inet_aton(host)
            + port.to_bytes(2, "big")
        )

    def _relay_datagrams(self) -> None:
        """Forward datagrams for as long as the control connection is open.

        RFC 1928 section 7 wraps each one in a header naming its destination,
        which is stripped on the way out and put back on the way in. The
        association belongs to this control connection, so closing it ends the
        relay — which is exactly what a real proxy does, and what the client is
        relied upon to keep open.
        """
        server = cast(Socks5Server, self.server)
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        relay.settimeout(0.5)
        self._reply(REPLY_SUCCEEDED, relay.getsockname())

        client_address: tuple[str, int] | None = None
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(0.5)
        self.request.settimeout(0.5)
        try:
            while True:
                # The control connection ending is the signal to stop; a real
                # proxy tears the association down at the same moment.
                with contextlib.suppress(TimeoutError, OSError):
                    if not self.request.recv(1, socket.MSG_PEEK):
                        return

                with contextlib.suppress(TimeoutError, OSError):
                    datagram, source = relay.recvfrom(65536)
                    client_address = source
                    target = self._parse_udp_header(datagram)
                    if target is not None:
                        destination, payload = target
                        server.datagrams_relayed.append(destination)
                        upstream.sendto(payload, destination)

                with contextlib.suppress(TimeoutError, OSError):
                    answer, source = upstream.recvfrom(65536)
                    if client_address is not None:
                        relay.sendto(_udp_header(source) + answer, client_address)
        finally:
            relay.close()
            upstream.close()

    @staticmethod
    def _parse_udp_header(
        datagram: bytes,
    ) -> tuple[tuple[str, int], bytes] | None:
        """The destination and payload of a wrapped datagram, or None."""
        if len(datagram) < 10 or datagram[2] != 0x00:
            # A non-zero fragment number asks for reassembly, which this does
            # not do and no QUIC client needs.
            return None
        if datagram[3] == ADDRESS_IPV4:
            host = socket.inet_ntop(socket.AF_INET, datagram[4:8])
            rest = 8
        elif datagram[3] == ADDRESS_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, datagram[4:20])
            rest = 20
        else:
            return None
        port = int.from_bytes(datagram[rest : rest + 2], "big")
        return (host, port), datagram[rest + 2 :]

    def _connect_and_pump(self, target: tuple[str, int]) -> None:
        server = cast(Socks5Server, self.server)
        server.connections.append(target)
        try:
            upstream = socket.create_connection(target, timeout=30)
        except OSError:
            self._reply(REPLY_GENERAL_FAILURE)
            return
        with upstream:
            self._reply(REPLY_SUCCEEDED)
            self._pump(self.request, upstream)

    @staticmethod
    def _pump(client: socket.socket, upstream: socket.socket) -> None:
        """Copy bytes each way until either side closes."""

        def forward(source: socket.socket, sink: socket.socket) -> None:
            try:
                while chunk := source.recv(65536):
                    sink.sendall(chunk)
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    sink.shutdown(socket.SHUT_WR)

        upstream_to_client = threading.Thread(
            target=forward, args=(upstream, client), daemon=True
        )
        upstream_to_client.start()
        forward(client, upstream)
        upstream_to_client.join(timeout=30)


def _udp_header(source: tuple[str, int]) -> bytes:
    """The RFC 1928 section 7 header naming where a datagram came from."""
    return (
        bytes([0x00, 0x00, 0x00, ADDRESS_IPV4])
        + socket.inet_aton(source[0])
        + source[1].to_bytes(2, "big")
    )


class Socks5Server(socketserver.ThreadingTCPServer):
    """A SOCKS5 proxy that records what passed through it."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self, username: str = "", password: str = "", relay_udp: bool = False
    ) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.username = username
        self.password = password
        # Off by default, so that the tests which expect a CONNECT-only proxy
        # keep describing one — that is what most SOCKS5 proxies are.
        self.relay_udp = relay_udp
        # What the tests assert on.
        self.connections: list[tuple[str, int]] = []
        self.credentials_seen: list[tuple[str, str]] = []
        self.offered_methods: list[set[int]] = []
        self.commands_seen: list[int] = []
        self.datagrams_relayed: list[tuple[str, int]] = []

    @property
    def url(self) -> str:
        """The proxy as Chromium's proxy rules would name it."""
        return f"socks5://127.0.0.1:{self.server_address[1]}"


@contextmanager
def running(
    username: str = "", password: str = "", relay_udp: bool = False
) -> Iterator[Socks5Server]:
    """A SOCKS5 proxy for the duration of the block."""
    server = Socks5Server(username, password, relay_udp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
