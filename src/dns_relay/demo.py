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
    # 离线伪上游：固定返回演示 IPv4，不访问公网，也不是通用 DNS 服务器。
    def __init__(self, port: int = 0) -> None:
        # port=0 由系统分配空闲端口；保存实际地址供 Relay 转发使用。
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", port))
        self.socket.settimeout(0.2)
        self.address = self.socket.getsockname()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        # 后台线程接收请求，主线程可以继续启动 Relay 并发起演示查询。
        self.thread.start()

    def run(self) -> None:
        # 短超时用于检查停止标志；针对本演示产生的合法 A 请求组装回答。
        while not self.stop.is_set():
            try:
                packet, client = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            query = parse_query(packet)
            # 三个分支中，只有未命中本地表的请求应到达这里。
            response = build_local_a_response(query, "203.0.113.9")
            self.socket.sendto(response, client)

    def close(self) -> None:
        # 通知停止、释放端口，并限时等待后台线程结束。
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)


def request(address: tuple[str, int], name: str, transaction_id: int) -> bytes:
    # 演示专用客户端：每次创建独立 UDP Socket，返回原始响应供 main 展示。
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(build_query(name, transaction_id), address)
        response, _ = client.recvfrom(4096)
        return response


def main() -> None:
    # 默认动态端口，避免与已运行的 5353/53 服务冲突；相同非零端口不允许。
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
    # 在同一进程中分别运行伪上游和真实 Relay，但仍通过本机 UDP Socket 通信。
    relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
    relay_thread.start()
    try:
        cases = [
            # 不同 ID 方便观察请求/响应对应；域名分别触发本地、屏蔽、转发。
            ("local.test", 0x1001, "本地 A 记录"),
            ("blocked.test", 0x1002, "本地屏蔽"),
            ("public.example", 0x1003, "上游转发"),
        ]
        print(f"DNS Relay 离线演示：{relay.address[0]}:{relay.address[1]}")
        for name, transaction_id, label in cases:
            # 解析头部、响应码和 A 地址，只打印观测结果，不伪造抓包证据。
            response = request(relay.address, name, transaction_id)
            header = DnsHeader.from_bytes(response)
            addresses = parse_a_answers(response)
            print(
                f"[{label}] name={name} id=0x{header.transaction_id:04x} "
                f"rcode={response_code(response)} answers={addresses or '-'}"
            )
    finally:
        # 演示查询结束或异常时，清理已进入此 try 所管理的服务与线程。
        relay.shutdown()
        relay_thread.join(timeout=2)
        upstream.close()


if __name__ == "__main__":
    # python -m src.dns_relay.demo 可独立运行，无需另开 Relay 终端。
    main()
