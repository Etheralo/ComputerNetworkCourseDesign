"""Minimal DNS wire-format parsing and response construction.

The relay intentionally implements only the pieces needed by the assignment:
one-question queries, local IPv4 answers, and DNS error replies. Unknown query
types are forwarded byte-for-byte and therefore do not need to be understood.
"""

from __future__ import annotations

from dataclasses import dataclass
import socket
import struct


# DNS 头由 6 个 16 位无符号整数构成，共 12 字节。
# A=IPv4，IN=Internet；响应码依次表示成功、格式错误、服务失败、域名不存在。
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
    # 与线上头部顺序一致：事务 ID、标志、问题/回答/权威/附加记录数量。
    transaction_id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    @classmethod
    def from_bytes(cls, packet: bytes) -> "DnsHeader":
        # 先检查长度，再解包；! 表示网络大端序，6H 表示六个 unsigned short。
        if len(packet) < DNS_HEADER_SIZE:
            raise DnsFormatError("DNS packet is shorter than the 12-byte header")
        return cls(*struct.unpack("!6H", packet[:DNS_HEADER_SIZE]))

    def to_bytes(self) -> bytes:
        # 按协议字段顺序将 Python 整数打包为可发送的二进制头部。
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
    # name/type/class 是解析值；wire 保留问题原始字节供构造响应使用。
    # end_offset 指向问题后第一个字节，便于继续遍历资源记录。
    name: str
    query_type: int
    query_class: int
    wire: bytes
    end_offset: int


@dataclass(frozen=True)
class DnsQuery:
    # 将头部、单个问题和完整原始报文组合起来；转发时无需重新编码。
    header: DnsHeader
    question: DnsQuestion
    packet: bytes


def encode_name(name: str) -> bytes:
    """Encode a presentation-format domain name into DNS labels."""
    normalized = name.rstrip(".")
    # 根域名仅用零字节表示；普通域名按“长度 + 标签内容”逐段编码。
    if not normalized:
        return b"\x00"
    encoded = bytearray()
    for label in normalized.split("."):
        # 此处不自动转换国际化域名；非 ASCII 域名需由调用者先转 punycode。
        try:
            raw_label = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise DnsFormatError("domain names must be ASCII or punycode") from exc
        if not raw_label or len(raw_label) > 63:
            raise DnsFormatError("DNS labels must contain between 1 and 63 bytes")
        encoded.append(len(raw_label))
        encoded.extend(raw_label)
    encoded.append(0)
    # 名称总长度包括各段长度字节和最终根域零字节。
    if len(encoded) > 255:
        raise DnsFormatError("encoded domain name exceeds 255 bytes")
    return bytes(encoded)


def decode_name(packet: bytes, offset: int, max_jumps: int = 20) -> tuple[str, int]:
    """Decode a possibly compressed DNS name and return (name, next_offset)."""
    labels: list[str] = []
    # position 跟随压缩指针移动；next_offset 保留原位置读完名称后的偏移。
    # 两者不能混用，否则读取 QTYPE/QCLASS 或后续记录时会错位。
    position = offset
    next_offset: int | None = None
    visited: set[int] = set()
    jumps = 0
    wire_length = 1

    while True:
        # 每次读取前检查边界，避免截断包造成越界。
        if position >= len(packet):
            raise DnsFormatError("domain name extends beyond packet")
        length = packet[position]
        if length & 0xC0 == 0xC0:
            # 高两位 11 表示压缩指针；其余 14 位为相对整个报文的目标偏移。
            if position + 1 >= len(packet):
                raise DnsFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[position + 1]
            if pointer >= len(packet):
                raise DnsFormatError("compression pointer is out of bounds")
            if pointer in visited or jumps >= max_jumps:
                # 已访问地址和跳转次数双重限制，防止指针循环耗尽处理时间。
                raise DnsFormatError("compression pointer loop detected")
            visited.add(pointer)
            jumps += 1
            if next_offset is None:
                # 原始名称在这两个指针字节后结束，后续字段不在指针目标后。
                next_offset = position + 2
            position = pointer
            continue
        if length & 0xC0:
            # 01/10 开头的标签形式不在本项目支持范围内。
            raise DnsFormatError("unsupported DNS label type")
        position += 1
        if length == 0:
            # 零长度标签表示名称结束。
            if next_offset is None:
                next_offset = position
            break
        if length > 63 or position + length > len(packet):
            raise DnsFormatError("invalid or truncated DNS label")
        raw_label = packet[position : position + length]
        # 普通标签直接解码，并累加解压后的名称长度以限制异常输入。
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
    # Question = QNAME（变长）+ QTYPE（2 字节）+ QCLASS（2 字节）。
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
    # 本项目仅接受单问题报文；这里只解析头部和问题，不完整校验所有区段。
    # QR 是否为查询由服务端 resolve 检查，不能仅凭本函数认定报文是请求。
    header = DnsHeader.from_bytes(packet)
    if header.question_count != 1:
        raise DnsFormatError("the relay accepts exactly one DNS question")
    question = parse_question(packet)
    return DnsQuery(header=header, question=question, packet=packet)


def _response_flags(request_flags: int, rcode: int) -> int:
    # 0x8000: QR=1；0x7800: 保留 OPCODE；0x0100: 保留 RD。
    # 0x0080: RA=1；不设置 AA。RA 表示可借助上游提供递归服务，
    # 不表示本程序自己逐级查询根域、顶级域和权威服务器。
    # QR=1, preserve OPCODE and RD, advertise recursion availability, no AA.
    return 0x8000 | (request_flags & 0x7800) | (request_flags & 0x0100) | 0x0080 | rcode


def build_local_a_response(query: DnsQuery, address: str, ttl: int = 60) -> bytes:
    # 将点分十进制地址转为 4 字节；本地响应保留请求 ID，返回一个 Answer。
    packed_address = socket.inet_aton(address)
    header = DnsHeader(
        transaction_id=query.header.transaction_id,
        flags=_response_flags(query.header.flags, RCODE_NOERROR),
        question_count=1,
        answer_count=1,
        authority_count=0,
        additional_count=0,
    )
    # RR = NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA。
    # 0xC00C 指向报文偏移 12 的问题域名；TTL 为 32 位秒数，默认 60 秒。
    # !HHHLH 中三个 H 为 16 位，L 为 32 位，末尾 H 表示 4 字节 RDATA 长度。
    answer = struct.pack("!HHHLH", 0xC00C, TYPE_A, CLASS_IN, ttl, 4) + packed_address
    return header.to_bytes() + query.question.wire + answer


def build_error_response(packet: bytes, rcode: int) -> bytes:
    """Build FORMERR/NXDOMAIN/SERVFAIL while preserving any safe query fields."""
    # 即使头部被截断，只要前两个字节存在，就尽量保留客户端事务 ID。
    transaction_id = struct.unpack("!H", packet[:2])[0] if len(packet) >= 2 else 0
    request_flags = struct.unpack("!H", packet[2:4])[0] if len(packet) >= 4 else 0
    question_wire = b""
    question_count = 0
    if len(packet) >= DNS_HEADER_SIZE:
        # 只在单问题能解析时复制问题；解析失败则返回 QD=0 的错误头。
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
    # 构造一个问题、零个回答的请求；0x0100 表示 RD=1（请求递归）。
    header = DnsHeader(transaction_id, 0x0100, 1, 0, 0, 0)
    return header.to_bytes() + encode_name(name) + struct.pack("!HH", query_type, CLASS_IN)


def response_code(packet: bytes) -> int:
    # 基础 DNS RCODE 位于 flags 的最低 4 位；此处不解析 EDNS 扩展响应码。
    return DnsHeader.from_bytes(packet).flags & 0x000F


def parse_a_answers(packet: bytes) -> list[str]:
    """Extract uncompressed IPv4 RDATA values for display and tests."""
    header = DnsHeader.from_bytes(packet)
    offset = DNS_HEADER_SIZE
    # 先跨过全部问题，再按 Answer 数量逐条遍历；不提取 Authority/Additional。
    for _ in range(header.question_count):
        question = parse_question(packet, offset)
        offset = question.end_offset
    answers: list[str] = []
    for _ in range(header.answer_count):
        # NAME 可能压缩；名称后的固定字段共 10 字节，之后是变长 RDATA。
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
            # 只展示 IPv4；其他类型按 RDLENGTH 跳过，并不表示响应无效。
            answers.append(socket.inet_ntoa(packet[data_start:data_end]))
        offset = data_end
    return answers
