"""Offline demonstration of all three DNS relay branches."""

from __future__ import annotations

import argparse
import socket
import threading

from .dns_codec import (
    DnsHeader,
    build_local_a_response,
    build_query,
    parse_a_answers,
    parse_query,
    response_code,
)
from .local_table import LocalTable
from .server import DnsRelayServer


class DemoUpstream:
    def __init__(self, port: int = 0) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", port))
        self.socket.settimeout(0.2)
        self.address = self.socket.getsockname()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                packet, client = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            query = parse_query(packet)
            response = build_local_a_response(query, "203.0.113.9")
            self.socket.sendto(response, client)

    def close(self) -> None:
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)


def request(address: tuple[str, int], name: str, transaction_id: int) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(build_query(name, transaction_id), address)
        response, _ = client.recvfrom(4096)
        return response


def main() -> None:
    parser = argparse.ArgumentParser(description="离线展示 DNS Relay 的三个处理分支")
    parser.add_argument("--relay-port", type=int, default=0, help="0 表示自动选择端口")
    parser.add_argument("--upstream-port", type=int, default=0, help="0 表示自动选择端口")
    args = parser.parse_args()
    if args.relay_port and args.relay_port == args.upstream_port:
        parser.error("relay and upstream ports must differ")

    upstream = DemoUpstream(args.upstream_port)
    upstream.start()
    relay = DnsRelayServer(
        "127.0.0.1",
        args.relay_port,
        str(upstream.address[0]),
        int(upstream.address[1]),
        LocalTable.load("config/dnsrelay.txt"),
        upstream_timeout=0.5,
        max_workers=4,
    )
    relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
    relay_thread.start()
    try:
        cases = [
            ("local.test", 0x1001, "本地 A 记录"),
            ("blocked.test", 0x1002, "本地屏蔽"),
            ("public.example", 0x1003, "上游转发"),
        ]
        print(f"DNS Relay 离线演示：{relay.address[0]}:{relay.address[1]}")
        for name, transaction_id, label in cases:
            response = request(relay.address, name, transaction_id)
            header = DnsHeader.from_bytes(response)
            addresses = parse_a_answers(response)
            print(
                f"[{label}] name={name} id=0x{header.transaction_id:04x} "
                f"rcode={response_code(response)} answers={addresses or '-'}"
            )
    finally:
        relay.shutdown()
        relay_thread.join(timeout=2)
        upstream.close()


if __name__ == "__main__":
    main()
