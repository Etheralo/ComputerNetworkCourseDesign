# DNS Relay 课程设计报告

## 1. 实验目标与环境

本实验使用 Python 标准库实现 TCP Client-Server 通信和 UDP DNS Relay，通过手工解析 RFC 1035 关键字段理解应用层协议与 Socket 编程。开发验证环境为 macOS、Python 3.13.5；代码要求 Python 3.10 及以上。成员姓名与具体分工请在提交前按实际情况补入验收记录。

## 2. 总体架构

DNS Client 将查询发到 Relay。Relay 解析 12 字节 Header 和单个 Question，规范化域名后查询本地表：普通 IPv4 命中时构造 A Answer；`0.0.0.0` 命中时构造 NXDOMAIN；未命中或非 A/IN 时将原始报文转发给真实上游。上游超时返回 SERVFAIL，非法报文返回 FORMERR。

代码分层如下：

- `dns_codec.py`：名称编解码、Header/Question 解析、响应构造。
- `local_table.py`：读取并规范化 `dnsrelay.txt`。
- `server.py`：UDP 监听、有限线程池、分支处理、上游通信和日志。
- `socket_demo/`：基于换行分帧的 TCP 连续收发示例。

## 3. 协议设计

本地响应保持请求 Transaction ID、OPCODE、RD 和 Question，设置 QR 与 RA，不设置 AA。A Answer 使用 `0xC00C` 指针引用 Question 的 QNAME，TTL 为 60 秒，RDATA 为 4 字节 IPv4。名称解析检查标签长度、包边界、压缩指针越界和循环，最多允许 20 次指针跳转。

每个上游任务创建独立且 `connect` 到指定上游的 UDP Socket，因此内核只接收该来源的数据；程序再核对 QR 与 Transaction ID。主线程只接收和分派，固定线程池避免线程数量无限增长，待处理任务也由有界信号量限制。

## 4. 测试结果

2026-09-08 执行 `make test`，19 项测试全部通过。自动测试使用本机临时端口和伪上游 DNS，不依赖公网。

| 要求 | 自动化证据 | 结果 |
|---|---|---|
| TCP 连续收发与 `exit` | `test_multiple_messages_and_exit_close_cleanly` | 通过 |
| 本地 A 与不访问上游 | `test_known_domain_returns_local_address_without_upstream` | 通过 |
| `0.0.0.0` 返回 NXDOMAIN | `test_zero_address_returns_nxdomain` | 通过 |
| 未命中、AAAA、非标准 OPCODE 转发 | 三项 forwarding 集成测试 | 通过 |
| 截断/非法报文 | codec 与 FORMERR 测试 | 通过 |
| ID 保持与错误 ID 拒绝 | codec、forwarding、mismatched-ID 测试 | 通过 |
| 上游不可达 | `test_upstream_timeout_returns_servfail` | 通过 |
| 大小写匹配 | `test_case_insensitive_local_match` | 通过 |
| 并发请求隔离 | 20 个并发 ID 的集成测试 | 通过 |

`make demo` 进一步在同一进程启动伪上游和真实 Relay Socket，重复验证三个核心分支。真实公网 DNS 的可达性和 Wireshark 字段截图依赖现场网络环境，不能由离线测试替代；按 [展示与使用说明](展示与使用说明.md) 采集并放入 `docs/captures/`。

此外，系统 `dig 9.10.6` 已直接查询实际 Relay 进程，独立确认 `local.test` 为 `NOERROR/ANSWER=1` 且地址为 `10.0.0.123`，`blocked.test` 为 `NXDOMAIN/ANSWER=0`；另一次查询经 Relay 转发到 `8.8.8.8:53`，得到 `NOERROR/ANSWER=1`，日志分支为 `upstream`。脱敏原始输出保存在 [captures/dig_verification.txt](captures/dig_verification.txt)。公网地址值随网络环境变化，不属于固定断言。当前 macOS 环境拒绝访问 `/dev/bpf0`，因此不能把这份文本验证冒充为真实 pcap；现场仍需按清单完成抓包。

## 5. 已知限制与改进方向

当前本地解析限定单 Question，且只生成 A/IN 记录；其他合法类型直接转发。未实现缓存、DNS over TCP、IPv6 本地记录和 EDNS 专门处理。后续可增加带 TTL 的缓存、上游 TCP 重试、统计界面和配置热加载，但这些增强不影响课程要求的三个核心分支。

## 6. 结论

实验完成了 TCP Socket 的连接与连续通信，也完成了 DNS 本地解析、域名屏蔽和上游转发。自动测试证明异常输入不会使服务崩溃，超时与错误响应 ID 不会被误返回，并发请求的 Transaction ID 不串线。最终验收仍需在展示机器上确认真实上游可达，并保存经过脱敏的 Wireshark 证据。
