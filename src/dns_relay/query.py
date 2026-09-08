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
    normalized_type = query_type.upper()
    if normalized_type not in QUERY_TYPES:
        choices = ", ".join(QUERY_TYPES)
        raise ValueError(f"unsupported query type {query_type!r}; choose from {choices}")
    if transaction_id is None:
        transaction_id = secrets.randbelow(0x10000)
    packet = build_query(name, transaction_id, QUERY_TYPES[normalized_type])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(packet, (host, port))
        response, _ = client.recvfrom(4096)
    header = DnsHeader.from_bytes(response)
    if header.transaction_id != transaction_id:
        raise DnsFormatError(
            f"transaction ID mismatch: expected 0x{transaction_id:04x}, "
            f"got 0x{header.transaction_id:04x}"
        )
    return response


def main() -> None:
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
        print("answers=" + ",".join(parse_a_answers(response)))


if __name__ == "__main__":
    main()
