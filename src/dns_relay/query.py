"""Small command-line DNS client for testing the local relay."""

from __future__ import annotations

import argparse
import secrets
import socket

from .dns_codec import (
    DnsFormatError,
    DnsHeader,
    build_query,
    parse_a_answers,
    response_code,
)


# 命令行类型名称到 DNS 数值的映射；能发起这些查询不代表能展示所有 RDATA。
QUERY_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "AAAA": 28,
}


def query_relay(
    host: str,
    port: int,
    name: str,
    query_type: str,
    timeout: float,
    transaction_id: int | None = None,
) -> bytes:
    # 校验类型并统一大小写；调用者未指定 ID 时生成一个 16 位随机事务 ID。
    normalized_type = query_type.upper()
    if normalized_type not in QUERY_TYPES:
        choices = ", ".join(QUERY_TYPES)
        raise ValueError(f"unsupported query type {query_type!r}; choose from {choices}")
    if transaction_id is None:
        transaction_id = secrets.randbelow(0x10000)
    packet = build_query(name, transaction_id, QUERY_TYPES[normalized_type])
    # 一次 UDP 查询：发送后等待一个响应；该工具不实现重传。
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(packet, (host, port))
        response, _ = client.recvfrom(4096)
    header = DnsHeader.from_bytes(response)
    # 校验 ID 对应本次请求；此简易客户端未校验 recvfrom 返回的来源地址。
    if header.transaction_id != transaction_id:
        raise DnsFormatError(
            f"transaction ID mismatch: expected 0x{transaction_id:04x}, "
            f"got 0x{header.transaction_id:04x}"
        )
    return response


def main() -> None:
    # host/port 为 Relay 地址；name 必填；type 默认 A；timeout 是客户端等待秒数。
    # --id 接受十进制或 0x 前缀十六进制；通常客户端超时应大于 Relay 上游超时。
    parser = argparse.ArgumentParser(description="Query a DNS relay over UDP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--name", required=True)
    parser.add_argument("--type", default="A", dest="query_type")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--id", type=lambda value: int(value, 0), dest="transaction_id")
    args = parser.parse_args()

    response = query_relay(
        args.host,
        args.port,
        args.name,
        args.query_type,
        args.timeout,
        args.transaction_id,
    )
    header = DnsHeader.from_bytes(response)
    flags = header.flags
    # 位移并 &1 提取单个标志位：QR=响应，RD=请求递归，RA=递归可用。
    # qd/an 为问题数/回答数；rcode=0 不保证 an>0，也不表示一定有 IPv4 地址。
    print(
        f"id=0x{header.transaction_id:04x} "
        f"qr={(flags >> 15) & 1} "
        f"rd={(flags >> 8) & 1} "
        f"ra={(flags >> 7) & 1} "
        f"rcode={response_code(response)} "
        f"qd={header.question_count} "
        f"an={header.answer_count}"
    )
    if args.query_type.upper() == "A":
        # 仅 A 查询额外提取 IPv4；AAAA 等仍显示头部，不解码其记录内容。
        print("answers=" + ",".join(parse_a_answers(response)))


if __name__ == "__main__":
    # python -m src.dns_relay.query 的执行入口。
    main()
