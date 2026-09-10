"""Concurrent UDP DNS relay with local A-record overrides."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import logging
import socket
import threading
import time

# 优先支持 python -m 的包内导入；下面的备用导入兼容直接运行文件。
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
    # 将转发阶段内部处理的超时/报文错误统一交给 resolve 生成 SERVFAIL。
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
        # 配置校验及主机名到 IPv4 的解析在启动阶段进行。
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.upstream_address = (socket.gethostbyname(upstream_host), upstream_port)
        bind_ip = socket.gethostbyname(host)
        # 拦截明显的上游指回自身配置；不是遍历所有网卡的完整环路检测。
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
        # Event 在主循环与关闭调用之间传递停止信号。
        # 线程池控制同时执行数量；信号量额外限制运行中 + 排队中的任务总数。
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dns-relay"
        )
        self._pending = threading.BoundedSemaphore(max_workers * 4)
        # SOCK_DGRAM 为 UDP：一次 recvfrom 读取一个数据报及其来源地址。
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, port))
        self._socket.settimeout(0.2)
        # 短接收超时用于定期检查停止标志，不是上游 DNS 请求超时。

    @property
    def address(self) -> tuple[str, int]:
        # 返回真实绑定地址；若构造时 port=0，这里可获取系统分配的端口。
        host, port = self._socket.getsockname()
        return str(host), int(port)

    def serve_forever(self) -> None:
        # 主线程负责接包和分派，耗时的上游等待由工作线程承担。
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
                    # 容量用尽立即返回 SERVFAIL，不让队列无限增长。
                    response = build_error_response(packet, RCODE_SERVFAIL)
                    self._safe_send(response, client)
                    self.logger.warning("client=%s:%d branch=overloaded result=SERVFAIL", *client)
                    continue
                future = self._executor.submit(self._handle_request, packet, client)
                # 无论任务成功还是异常结束，都归还一个容量名额。
                future.add_done_callback(lambda _future: self._pending.release())
        finally:
            # 取消尚未执行的任务，等待已运行任务结束并回收线程池。
            self._executor.shutdown(wait=True, cancel_futures=True)

    def shutdown(self) -> None:
        # 设置停止标志并关闭监听 Socket；调用者可再 join 主循环所在的线程。
        self._stop.set()
        try:
            self._socket.close()
        except OSError:
            pass

    def resolve(self, packet: bytes) -> tuple[bytes, str]:
        """Resolve one packet and return (wire response, processing branch)."""
        try:
            query = parse_query(packet)
            # QR 的最高位为 1 表示响应，不能把它当查询再次转发。
            if query.header.flags & 0x8000:
                raise DnsFormatError("received a response where a query was expected")
        except DnsFormatError:
            return build_error_response(packet, RCODE_FORMERR), "formerr"

        question = query.question
        local_address = None
        opcode = (query.header.flags >> 11) & 0xF
        # 本地表仅覆盖标准查询 OPCODE=0、A 类型、IN 类别。
        # AAAA 等请求即使命中同名屏蔽条目，也不会走本地处理分支。
        if (
            opcode == 0
            and question.query_type == TYPE_A
            and question.query_class == CLASS_IN
        ):
            local_address = self.table.lookup(question.name)
        if local_address == "0.0.0.0":
            # 约定的屏蔽值：返回 NXDOMAIN，而不是 A=0.0.0.0。
            return build_error_response(packet, RCODE_NXDOMAIN), "local-nxdomain"
        if local_address is not None:
            # 命中普通 IPv4：自己组装本地 A 响应，不访问上游。
            return build_local_a_response(query, local_address), "local-a"

        try:
            return self._forward(packet, query.header.transaction_id), "upstream"
        except UpstreamError:
            # 此处捕获 _forward 显式转换的 UpstreamError，并返回服务失败。
            return build_error_response(packet, RCODE_SERVFAIL), "upstream-servfail"

    def _forward(self, packet: bytes, transaction_id: int) -> bytes:
        # 单调时钟不受系统校时影响；错 ID 报文不会重置整段超时预算。
        deadline = time.monotonic() + self.upstream_timeout
        # 每个请求独立使用 UDP Socket，隔离并发请求，不需要重写事务 ID。
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
            # UDP connect 只指定对端并限制来源，不执行 TCP 三次握手。
            # 注意：本行在下面 try 外，连接设置本身的 OSError 不会被其转换。
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
                    # 当前验证头部 ID 和 QR，不是完整的 Question/Answer 一致性校验。
                    if header.transaction_id != transaction_id or not (header.flags & 0x8000):
                        continue
                    # 合格响应原样返回；这里未实现 TC 截断后的 TCP 回退或缓存。
                    return response
            except (OSError, DnsFormatError) as exc:
                raise UpstreamError(str(exc)) from exc

    def _handle_request(self, packet: bytes, client: tuple[str, int]) -> None:
        # 工作线程入口：提取日志字段 -> resolve -> 回包 -> 记录耗时与分支。
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
            # 日志提取失败不阻止 resolve 生成格式错误响应。
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
        # 用最初的监听 Socket 回复原客户端；关闭期间发送失败不再刷错误日志。
        try:
            self._socket.sendto(packet, client)
        except OSError:
            if not self._stop.is_set():
                self.logger.exception("failed to reply to client=%s:%d", *client)


def build_argument_parser() -> argparse.ArgumentParser:
    # host/port 控制本机 UDP 监听；upstream/upstream-port 控制转发目标。
    # table 为本地表路径；timeout 为上游等待秒数；workers 为线程上限。
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
    # 命令入口：解析参数、设置日志、加载一次配置、创建服务、进入接收循环。
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
    # 被测试或 demo 导入时不会自动启动服务。
    main()
