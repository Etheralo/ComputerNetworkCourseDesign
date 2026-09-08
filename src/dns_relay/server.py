"""Concurrent UDP DNS relay with local A-record overrides."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import logging
import socket
import threading
import time

try:
    from .dns_codec import (
        CLASS_IN,
        RCODE_FORMERR,
        RCODE_NXDOMAIN,
        RCODE_SERVFAIL,
        TYPE_A,
        DnsFormatError,
        DnsHeader,
        build_error_response,
        build_local_a_response,
        parse_query,
    )
    from .local_table import LocalTable
except ImportError:  # Allow: python3 src/dns_relay/server.py
    from dns_codec import (  # type: ignore
        CLASS_IN,
        RCODE_FORMERR,
        RCODE_NXDOMAIN,
        RCODE_SERVFAIL,
        TYPE_A,
        DnsFormatError,
        DnsHeader,
        build_error_response,
        build_local_a_response,
        parse_query,
    )
    from local_table import LocalTable  # type: ignore


LOG = logging.getLogger("dns_relay")
QUERY_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA"}


class UpstreamError(RuntimeError):
    pass


class DnsRelayServer:
    """A stoppable DNS relay suitable for both the CLI and integration tests."""

    def __init__(
        self,
        host: str,
        port: int,
        upstream_host: str,
        upstream_port: int,
        table: LocalTable,
        *,
        upstream_timeout: float = 2.0,
        max_workers: int = 16,
        max_packet_size: int = 4096,
        logger: logging.Logger = LOG,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.upstream_address = (socket.gethostbyname(upstream_host), upstream_port)
        bind_ip = socket.gethostbyname(host)
        if port == upstream_port and (
            self.upstream_address[0] == bind_ip
            or (bind_ip == "0.0.0.0" and self.upstream_address[0].startswith("127."))
        ):
            raise ValueError("upstream DNS must not point back to the relay")
        self.table = table
        self.upstream_timeout = upstream_timeout
        self.max_packet_size = max_packet_size
        self.logger = logger
        self._stop = threading.Event()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dns-relay"
        )
        self._pending = threading.BoundedSemaphore(max_workers * 4)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, port))
        self._socket.settimeout(0.2)

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._socket.getsockname()
        return str(host), int(port)

    def serve_forever(self) -> None:
        self.logger.info(
            "listening=%s:%d upstream=%s:%d records=%d",
            *self.address,
            *self.upstream_address,
            len(self.table.records),
        )
        try:
            while not self._stop.is_set():
                try:
                    packet, client = self._socket.recvfrom(self.max_packet_size)
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                if not self._pending.acquire(blocking=False):
                    response = build_error_response(packet, RCODE_SERVFAIL)
                    self._safe_send(response, client)
                    self.logger.warning("client=%s:%d branch=overloaded result=SERVFAIL", *client)
                    continue
                future = self._executor.submit(self._handle_request, packet, client)
                future.add_done_callback(lambda _future: self._pending.release())
        finally:
            self._executor.shutdown(wait=True, cancel_futures=True)

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self._socket.close()
        except OSError:
            pass

    def resolve(self, packet: bytes) -> tuple[bytes, str]:
        """Resolve one packet and return (wire response, processing branch)."""
        try:
            query = parse_query(packet)
            if query.header.flags & 0x8000:
                raise DnsFormatError("received a response where a query was expected")
        except DnsFormatError:
            return build_error_response(packet, RCODE_FORMERR), "formerr"

        question = query.question
        local_address = None
        opcode = (query.header.flags >> 11) & 0xF
        if (
            opcode == 0
            and question.query_type == TYPE_A
            and question.query_class == CLASS_IN
        ):
            local_address = self.table.lookup(question.name)
        if local_address == "0.0.0.0":
            return build_error_response(packet, RCODE_NXDOMAIN), "local-nxdomain"
        if local_address is not None:
            return build_local_a_response(query, local_address), "local-a"

        try:
            return self._forward(packet, query.header.transaction_id), "upstream"
        except UpstreamError:
            return build_error_response(packet, RCODE_SERVFAIL), "upstream-servfail"

    def _forward(self, packet: bytes, transaction_id: int) -> bytes:
        deadline = time.monotonic() + self.upstream_timeout
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
            upstream_socket.connect(self.upstream_address)
            try:
                upstream_socket.send(packet)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise UpstreamError("upstream timed out")
                    upstream_socket.settimeout(remaining)
                    response = upstream_socket.recv(self.max_packet_size)
                    header = DnsHeader.from_bytes(response)
                    if header.transaction_id != transaction_id or not (header.flags & 0x8000):
                        continue
                    return response
            except (OSError, DnsFormatError) as exc:
                raise UpstreamError(str(exc)) from exc

    def _handle_request(self, packet: bytes, client: tuple[str, int]) -> None:
        started = time.monotonic()
        transaction_id = int.from_bytes(packet[:2], "big") if len(packet) >= 2 else 0
        domain = "-"
        query_type = "-"
        try:
            query = parse_query(packet)
            domain = query.question.name or "."
            query_type = QUERY_TYPE_NAMES.get(
                query.question.query_type, str(query.question.query_type)
            )
        except DnsFormatError:
            pass
        response, branch = self.resolve(packet)
        result = DnsHeader.from_bytes(response).flags & 0xF
        self._safe_send(response, client)
        elapsed_ms = (time.monotonic() - started) * 1000
        self.logger.info(
            "client=%s:%d id=0x%04x name=%s type=%s branch=%s upstream=%s:%d "
            "elapsed_ms=%.1f rcode=%d",
            client[0],
            client[1],
            transaction_id,
            domain,
            query_type,
            branch,
            self.upstream_address[0],
            self.upstream_address[1],
            elapsed_ms,
            result,
        )

    def _safe_send(self, packet: bytes, client: tuple[str, int]) -> None:
        try:
            self._socket.sendto(packet, client)
        except OSError:
            if not self._stop.is_set():
                self.logger.exception("failed to reply to client=%s:%d", *client)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="UDP DNS relay with local A records")
    parser.add_argument("--host", default="127.0.0.1", help="listen address")
    parser.add_argument("--port", type=int, default=5353, help="listen UDP port")
    parser.add_argument("--upstream", default="8.8.8.8", help="upstream DNS IPv4/host")
    parser.add_argument("--upstream-port", type=int, default=53)
    parser.add_argument("--table", default="config/dnsrelay.txt")
    parser.add_argument("--timeout", type=float, default=2.0, help="upstream timeout")
    parser.add_argument("--workers", type=int, default=16, help="worker thread limit")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    table = LocalTable.load(args.table)
    relay = DnsRelayServer(
        args.host,
        args.port,
        args.upstream,
        args.upstream_port,
        table,
        upstream_timeout=args.timeout,
        max_workers=args.workers,
    )
    try:
        relay.serve_forever()
    except KeyboardInterrupt:
        LOG.info("stopping DNS relay")
    finally:
        relay.shutdown()


if __name__ == "__main__":
    main()
