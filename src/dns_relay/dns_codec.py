"""Minimal DNS wire-format parsing and response construction.

The relay intentionally implements only the pieces needed by the assignment:
one-question queries, local IPv4 answers, and DNS error replies. Unknown query
types are forwarded byte-for-byte and therefore do not need to be understood.
"""

from __future__ import annotations

from dataclasses import dataclass
import socket
import struct


DNS_HEADER_SIZE = 12
TYPE_A = 1
CLASS_IN = 1
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3


class DnsFormatError(ValueError):
    """Raised when a DNS packet is malformed or unsupported locally."""


@dataclass(frozen=True)
class DnsHeader:
    transaction_id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    @classmethod
    def from_bytes(cls, packet: bytes) -> "DnsHeader":
        if len(packet) < DNS_HEADER_SIZE:
            raise DnsFormatError("DNS packet is shorter than the 12-byte header")
        return cls(*struct.unpack("!6H", packet[:DNS_HEADER_SIZE]))

    def to_bytes(self) -> bytes:
        return struct.pack(
            "!6H",
            self.transaction_id,
            self.flags,
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count,
        )


@dataclass(frozen=True)
class DnsQuestion:
    name: str
    query_type: int
    query_class: int
    wire: bytes
    end_offset: int


@dataclass(frozen=True)
class DnsQuery:
    header: DnsHeader
    question: DnsQuestion
    packet: bytes


def encode_name(name: str) -> bytes:
    """Encode a presentation-format domain name into DNS labels."""
    normalized = name.rstrip(".")
    if not normalized:
        return b"\x00"
    encoded = bytearray()
    for label in normalized.split("."):
        try:
            raw_label = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise DnsFormatError("domain names must be ASCII or punycode") from exc
        if not raw_label or len(raw_label) > 63:
            raise DnsFormatError("DNS labels must contain between 1 and 63 bytes")
        encoded.append(len(raw_label))
        encoded.extend(raw_label)
    encoded.append(0)
    if len(encoded) > 255:
        raise DnsFormatError("encoded domain name exceeds 255 bytes")
    return bytes(encoded)


def decode_name(packet: bytes, offset: int, max_jumps: int = 20) -> tuple[str, int]:
    """Decode a possibly compressed DNS name and return (name, next_offset)."""
    labels: list[str] = []
    position = offset
    next_offset: int | None = None
    visited: set[int] = set()
    jumps = 0
    wire_length = 1

    while True:
        if position >= len(packet):
            raise DnsFormatError("domain name extends beyond packet")
        length = packet[position]
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(packet):
                raise DnsFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[position + 1]
            if pointer >= len(packet):
                raise DnsFormatError("compression pointer is out of bounds")
            if pointer in visited or jumps >= max_jumps:
                raise DnsFormatError("compression pointer loop detected")
            visited.add(pointer)
            jumps += 1
            if next_offset is None:
                next_offset = position + 2
            position = pointer
            continue
        if length & 0xC0:
            raise DnsFormatError("unsupported DNS label type")
        position += 1
        if length == 0:
            if next_offset is None:
                next_offset = position
            break
        if length > 63 or position + length > len(packet):
            raise DnsFormatError("invalid or truncated DNS label")
        raw_label = packet[position : position + length]
        try:
            labels.append(raw_label.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise DnsFormatError("domain label is not ASCII") from exc
        wire_length += length + 1
        if wire_length > 255:
            raise DnsFormatError("decoded domain name exceeds 255 bytes")
        position += length

    return ".".join(labels), next_offset


def parse_question(packet: bytes, offset: int = DNS_HEADER_SIZE) -> DnsQuestion:
    name, name_end = decode_name(packet, offset)
    if name_end + 4 > len(packet):
        raise DnsFormatError("truncated DNS question")
    query_type, query_class = struct.unpack("!HH", packet[name_end : name_end + 4])
    end_offset = name_end + 4
    return DnsQuestion(
        name=name,
        query_type=query_type,
        query_class=query_class,
        wire=packet[offset:end_offset],
        end_offset=end_offset,
    )


def parse_query(packet: bytes) -> DnsQuery:
    header = DnsHeader.from_bytes(packet)
    if header.question_count != 1:
        raise DnsFormatError("the relay accepts exactly one DNS question")
    question = parse_question(packet)
    return DnsQuery(header=header, question=question, packet=packet)


def _response_flags(request_flags: int, rcode: int) -> int:
    # QR=1, preserve OPCODE and RD, advertise recursion availability, no AA.
    return 0x8000 | (request_flags & 0x7800) | (request_flags & 0x0100) | 0x0080 | rcode


def build_local_a_response(query: DnsQuery, address: str, ttl: int = 60) -> bytes:
    packed_address = socket.inet_aton(address)
    header = DnsHeader(
        transaction_id=query.header.transaction_id,
        flags=_response_flags(query.header.flags, RCODE_NOERROR),
        question_count=1,
        answer_count=1,
        authority_count=0,
        additional_count=0,
    )
    answer = struct.pack("!HHHLH", 0xC00C, TYPE_A, CLASS_IN, ttl, 4) + packed_address
    return header.to_bytes() + query.question.wire + answer


def build_error_response(packet: bytes, rcode: int) -> bytes:
    """Build FORMERR/NXDOMAIN/SERVFAIL while preserving any safe query fields."""
    transaction_id = struct.unpack("!H", packet[:2])[0] if len(packet) >= 2 else 0
    request_flags = struct.unpack("!H", packet[2:4])[0] if len(packet) >= 4 else 0
    question_wire = b""
    question_count = 0
    if len(packet) >= DNS_HEADER_SIZE:
        try:
            header = DnsHeader.from_bytes(packet)
            if header.question_count == 1:
                question = parse_question(packet)
                question_wire = question.wire
                question_count = 1
        except DnsFormatError:
            pass
    header = DnsHeader(
        transaction_id=transaction_id,
        flags=_response_flags(request_flags, rcode),
        question_count=question_count,
        answer_count=0,
        authority_count=0,
        additional_count=0,
    )
    return header.to_bytes() + question_wire


def build_query(name: str, transaction_id: int, query_type: int = TYPE_A) -> bytes:
    header = DnsHeader(transaction_id, 0x0100, 1, 0, 0, 0)
    return header.to_bytes() + encode_name(name) + struct.pack("!HH", query_type, CLASS_IN)


def response_code(packet: bytes) -> int:
    return DnsHeader.from_bytes(packet).flags & 0x000F


def parse_a_answers(packet: bytes) -> list[str]:
    """Extract uncompressed IPv4 RDATA values for display and tests."""
    header = DnsHeader.from_bytes(packet)
    offset = DNS_HEADER_SIZE
    for _ in range(header.question_count):
        question = parse_question(packet, offset)
        offset = question.end_offset
    answers: list[str] = []
    for _ in range(header.answer_count):
        _, name_end = decode_name(packet, offset)
        if name_end + 10 > len(packet):
            raise DnsFormatError("truncated resource record")
        record_type, record_class, _ttl, data_length = struct.unpack(
            "!HHLH", packet[name_end : name_end + 10]
        )
        data_start = name_end + 10
        data_end = data_start + data_length
        if data_end > len(packet):
            raise DnsFormatError("truncated resource record data")
        if record_type == TYPE_A and record_class == CLASS_IN and data_length == 4:
            answers.append(socket.inet_ntoa(packet[data_start:data_end]))
        offset = data_end
    return answers
