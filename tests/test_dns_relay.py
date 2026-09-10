from concurrent.futures import ThreadPoolExecutor
import socket
import threading
import unittest

from src.dns_relay.dns_codec import (
    DnsHeader,
    RCODE_FORMERR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    build_local_a_response,
    build_query,
    parse_a_answers,
    parse_query,
    response_code,
)
from src.dns_relay.local_table import LocalTable
from src.dns_relay.server import DnsRelayServer


class FakeUpstream:
    # 可控伪上游：记录原始请求，默认返回固定地址，可切换为错误事务 ID。
    def __init__(self, wrong_ids: bool = False):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.address = self.socket.getsockname()
        self.wrong_ids = wrong_ids
        self.requests: list[bytes] = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        # 用独立线程模拟网络上的上游服务，不依赖外网。
        self.thread.start()

    def _run(self):
        # 接收循环通过短超时检查停止状态；requests 用于验证是否真实转发。
        while not self.stop_event.is_set():
            try:
                packet, client = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self.requests.append(packet)
            query = parse_query(packet)
            response = build_local_a_response(query, "198.51.100.7")
            if self.wrong_ids:
                # 故意只替换头两个字节，模拟与查询不匹配的响应。
                response = b"\xff\xff" + response[2:]
            self.socket.sendto(response, client)

    def close(self):
        # 每个使用者应关闭 Socket 并回收后台线程，避免污染其他测试。
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=1)


class DnsRelayIntegrationTests(unittest.TestCase):
    def setUp(self):
        # 每个测试建立独立伪上游、Relay 和本地表；端口 0 避免固定端口冲突。
        self.upstream = FakeUpstream()
        self.upstream.start()
        self.relay = DnsRelayServer(
            "127.0.0.1",
            0,
            self.upstream.address[0],
            self.upstream.address[1],
            LocalTable({"local.test": "10.0.0.123", "blocked.test": "0.0.0.0"}),
            upstream_timeout=0.15,
            max_workers=8,
        )
        self.relay_thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
        self.relay_thread.start()

    def tearDown(self):
        # 每个集成测试结束后停止服务并等待后台线程。
        self.relay.shutdown()
        self.relay_thread.join(timeout=2)
        self.upstream.close()

    def query(self, packet: bytes) -> bytes:
        # 通过真实本机 UDP 数据报访问 Relay，而不是直接调用 resolve。
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(packet, self.relay.address)
            response, _ = client.recvfrom(4096)
            return response

    def test_known_domain_returns_local_address_without_upstream(self):
        # 同时断言答案正确、上游未收到请求，证明走本地分支。
        response = self.query(build_query("local.test", 0x1001))
        self.assertEqual(parse_a_answers(response), ["10.0.0.123"])
        self.assertEqual(self.upstream.requests, [])

    def test_zero_address_returns_nxdomain(self):
        # 屏蔽应为 RCODE=3、AN=0，不能作为普通 A 地址返回。
        response = self.query(build_query("blocked.test", 0x1002))
        self.assertEqual(response_code(response), RCODE_NXDOMAIN)
        self.assertEqual(DnsHeader.from_bytes(response).answer_count, 0)
        self.assertEqual(self.upstream.requests, [])

    def test_unknown_domain_is_forwarded_unchanged(self):
        # 比较上游收到的完整字节，并检查返回 ID 和固定地址。
        query = build_query("public.example", 0x1003)
        response = self.query(query)
        self.assertEqual(self.upstream.requests, [query])
        self.assertEqual(DnsHeader.from_bytes(response).transaction_id, 0x1003)
        self.assertEqual(parse_a_answers(response), ["198.51.100.7"])

    def test_non_a_query_is_forwarded_even_if_name_is_local(self):
        # AAAA=28；本测试验证请求转发，不证明伪上游提供了真实 AAAA 记录。
        query = build_query("local.test", 0x1004, query_type=28)
        self.query(query)
        self.assertEqual(self.upstream.requests, [query])

    def test_nonstandard_opcode_is_forwarded_instead_of_answered_locally(self):
        # 手动设置非标准查询操作码，确认不会错误套用本地 A 表。
        query = bytearray(build_query("local.test", 0x1006))
        query[2:4] = (0x1100).to_bytes(2, "big")  # OPCODE=2 and RD=1
        self.query(bytes(query))
        self.assertEqual(self.upstream.requests, [bytes(query)])

    def test_malformed_packet_returns_formerr_without_crashing(self):
        # 三字节短包不足 DNS 头长度，应返回 FORMERR 且保留可读 ID。
        response = self.query(b"\xab\xcd\x01")
        self.assertEqual(DnsHeader.from_bytes(response).transaction_id, 0xABCD)
        self.assertEqual(response_code(response), RCODE_FORMERR)

    def test_case_insensitive_local_match(self):
        # 通过完整 UDP 路径验证域名规范化生效。
        response = self.query(build_query("LOCAL.Test.", 0x1005))
        self.assertEqual(parse_a_answers(response), ["10.0.0.123"])
        self.assertEqual(self.upstream.requests, [])

    def test_concurrent_requests_keep_transaction_ids_separate(self):
        # 10 个客户端线程发出共 20 个不同 ID 请求，检查每个响应的归属。
        def one_request(transaction_id: int) -> int:
            response = self.query(build_query("public.example", transaction_id))
            return DnsHeader.from_bytes(response).transaction_id

        ids = list(range(0x2000, 0x2014))
        with ThreadPoolExecutor(max_workers=10) as executor:
            returned = list(executor.map(one_request, ids))
        self.assertEqual(returned, ids)


class DnsRelayFailureTests(unittest.TestCase):
    def test_upstream_timeout_returns_servfail(self):
        # 找到并释放本机 UDP 端口后作为不可用上游；可能触发拒绝或超时。
        # 因此此测试证明失败转 SERVFAIL，不保证实际等待完整超时时长。
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        unused_port = probe.getsockname()[1]
        probe.close()
        relay = DnsRelayServer(
            "127.0.0.1",
            0,
            "127.0.0.1",
            unused_port,
            LocalTable({}),
            upstream_timeout=0.05,
        )
        response, branch = relay.resolve(build_query("timeout.test", 0x3001))
        relay.shutdown()
        self.assertEqual(branch, "upstream-servfail")
        self.assertEqual(response_code(response), RCODE_SERVFAIL)

    def test_mismatched_upstream_id_is_not_returned(self):
        # 上游只回错误 ID；Relay 不得直接转回，应最终超时返回 SERVFAIL。
        upstream = FakeUpstream(wrong_ids=True)
        upstream.start()
        relay = DnsRelayServer(
            "127.0.0.1",
            0,
            upstream.address[0],
            upstream.address[1],
            LocalTable({}),
            upstream_timeout=0.05,
        )
        response, branch = relay.resolve(build_query("id.test", 0x3002))
        relay.shutdown()
        upstream.close()
        self.assertEqual(branch, "upstream-servfail")
        self.assertEqual(response_code(response), RCODE_SERVFAIL)


if __name__ == "__main__":
    unittest.main()
