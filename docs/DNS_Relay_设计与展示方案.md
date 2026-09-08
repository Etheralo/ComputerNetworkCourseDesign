# DNS Relay 课程设计实施与展示方案

## 1. 文档状态与设计目标

本文最初是课程设计的实施规划，现已按规划落地程序、构建入口、自动测试、报告和展示说明。2026-09-08 在 Python 3.13.5 上执行 19 项测试全部通过；真实公网 DNS 转发已验证。按当前安排，Wireshark 抓包后期在另一台电脑完成，不作为本阶段程序交付的阻塞项。

课程要求来自以下资料：

- [计算机网络课程设计课件](计算机网络课程设计课件.pdf)：完成 Client-Server Socket 通信和 DNS Relay，使用 Wireshark 分析报文。
- [RFC 1035](RFC1035.pdf)：DNS 报文结构、资源记录、名称编码以及 UDP/TCP 传输规则。
- [第14章 DNS域名系统](第14章%20DNS域名系统.pdf)：DNS 查询、递归/迭代、缓存和报文格式背景。
- [课程设计验收记录](课程设计验收记录.doc)：记录成员职责、开发环境、功能、测试和自我评定。

最终交付目标：

1. 一个可交互运行的 TCP Client-Server Socket 示例。
2. 一个基于 UDP 的 DNS Relay。
3. 自动测试、Wireshark 抓包证据和课程设计报告。

## 2. 技术路线与范围

推荐使用 Python 3 标准库：`socket` 负责通信，`struct` 负责 DNS 字段编解码，`ipaddress` 负责地址校验，`concurrent.futures` 负责有限并发。第一阶段不引入第三方 DNS 库，因为手工解析关键字段更能体现对 RFC 1035 的理解。

本项目是中继器，不是完整递归解析器。最小版本支持单 Question 的标准查询；本地表只回答 `A/IN`，其他合法请求原样转发上游。缓存、EDNS、DNS over TCP 和 IPv6 本地记录作为可选增强，不应阻塞基本验收。

规划目录：

```text
src/
├── socket_demo/
│   ├── server.py
│   └── client.py
└── dns_relay/
    ├── server.py          # 参数、监听、分派和日志
    ├── dns_codec.py       # Header、Question、Answer编解码
    └── local_table.py     # dnsrelay.txt加载与查询
config/
└── dnsrelay.txt
tests/
├── test_dns_codec.py
└── test_dns_relay.py
docs/
├── captures/
└── report.md
```

## 3. 第一阶段：Client-Server Socket 通信

使用 TCP 完成课件截图中的“连接、连续收发、输入 `exit`、正常关闭”过程。使用 `127.0.0.1:9000`，避免端口 80 的权限和占用问题。

服务端流程：`socket()` → `bind()` → `listen()` → `accept()` → 循环 `recv()/sendall()` → `close()`。

客户端流程：`socket()` → `connect()` → 循环读取输入并 `sendall()/recv()` → 输入 `exit` 后关闭。

验收时应同时显示两个终端，证明服务端能够记录客户端地址、接收多条消息、返回确认文本，并在客户端退出后释放连接。

## 4. 第二阶段：DNS Relay 架构

```text
DNS Client
    │ UDP query
    ▼
DNS Relay
    ├─ local IP = 0.0.0.0 ──> NXDOMAIN response
    ├─ local A record hit ───> locally built A response
    └─ miss/other query ─────> upstream DNS ──> original client
```

开发时监听 `127.0.0.1:5353`；功能稳定后再切换到端口 53。启动 Relay 前先保存真实上游 DNS 地址，且禁止把上游配置成 Relay 自己，避免转发环路。

本地表格式采用每行“IPv4地址 + 空白 + 域名”：

```text
0.0.0.0 blocked.test
10.0.0.123 local.test
```

每个请求按以下顺序处理：

1. 校验报文至少为 12 字节，解析 Header 和 Question。
2. 将域名转为小写并去除末尾的点，执行大小写无关匹配。
3. `A/IN` 命中普通地址：返回一个本地 A Answer。
4. `A/IN` 命中 `0.0.0.0`：返回 NXDOMAIN。
5. 未命中或不是 `A/IN`：将原始报文转发上游并把响应返回原客户端。
6. 格式错误返回 FORMERR；上游超时返回 SERVFAIL。

## 5. DNS 报文实现要点

- Header 固定 12 字节，使用网络字节序解析六个 16 位字段。
- 响应 Transaction ID 必须与请求一致，Question 原样回显。
- 本地响应设置 `QR=1`，保留 `OPCODE` 和 `RD`；支持转发时设置 `RA=1`，但不设置 `AA`。
- 本地命中时 `ANCOUNT=1`；NXDOMAIN 时 `ANCOUNT=0`、`RCODE=3`；超时时 `RCODE=2`。
- 本地 Answer 的 NAME 可使用 `0xC00C` 指针引用 Question 中的 QNAME，TYPE 为 A、CLASS 为 IN、TTL 建议 60 秒、RDLENGTH 为 4。
- 域名标签长度不得超过 63 字节；解析压缩指针时必须限制跳转次数并检查越界，防止死循环。
- 收到上游响应后核对来源地址和 Transaction ID。若响应设置了 `TC`，最小版本原样返回，让客户端决定是否通过 TCP 重试。

主监听线程只负责接收和分派。每个上游任务使用独立的临时 UDP Socket 和超时，从而自然绑定“客户端地址—请求—响应”，并使用有限大小线程池防止线程无限增长。

## 6. 计划运行命令

以下命令要在代码完成后写入根目录 README，并以实际参数为准：

```bash
# TCP Socket演示
python3 src/socket_demo/server.py --host 127.0.0.1 --port 9000
python3 src/socket_demo/client.py --host 127.0.0.1 --port 9000

# DNS Relay开发模式
python3 src/dns_relay/server.py \
  --host 127.0.0.1 --port 5353 \
  --upstream <真实上游DNS> --table config/dnsrelay.txt

# 直接查询Relay，避免操作系统DNS缓存干扰
dig @127.0.0.1 -p 5353 local.test A
dig @127.0.0.1 -p 5353 blocked.test A
dig @127.0.0.1 -p 5353 www.baidu.com A

# 自动测试
python3 -m unittest discover -s tests -v
```

切换到端口 53 前，应确认端口未被系统 DNS 服务占用。不要在 Relay 尚未验证时修改整机 DNS 设置，否则程序故障可能造成断网。

## 7. 测试矩阵与通过标准

| 编号 | 场景 | 预期结果 | 主要证据 |
|---|---|---|---|
| CS-01 | TCP客户端发送一条消息 | 服务端收到并回复 | 双终端日志 |
| CS-02 | 连续发送后输入`exit` | 多次收发成功且正常关闭 | 双终端日志 |
| DNS-01 | 查询`local.test A` | 返回`10.0.0.123`，不访问上游 | `dig`与抓包 |
| DNS-02 | 查询`blocked.test A` | 无Answer，`RCODE=3` | Wireshark字段 |
| DNS-03 | 查询公网A记录 | 出现两段通信并返回上游结果 | Relay日志与抓包 |
| DNS-04 | 查询AAAA或MX | 不误用本地A记录，转发上游 | 查询结果与抓包 |
| DNS-05 | 上游不可达 | 超时后返回`SERVFAIL` | 日志与`RCODE=2` |
| DNS-06 | 截断或非法报文 | 程序不崩溃，返回FORMERR或丢弃 | 自动测试 |
| DNS-07 | 大小写域名 | 本地匹配结果相同 | 自动测试 |
| DNS-08 | 多客户端并发 | 响应ID和客户端不串线 | 并发测试日志 |

每个结论至少保留一种可复查证据。Wireshark过滤器使用：

```text
tcp.port == 9000
udp.port == 53 || udp.port == 5353
```

## 8. 现场展示脚本（约6分钟）

1. **目标与架构（30秒）**：说明项目不是完整DNS服务器，而是“本地规则 + 上游转发”的中继器。
2. **TCP通信（60秒）**：启动服务端和客户端，发送两条消息，再输入`exit`。
3. **本地正常记录（45秒）**：查询`local.test`，展示返回地址；指出抓包中没有上游查询。
4. **本地域名屏蔽（45秒）**：查询`blocked.test`，在Wireshark展开Flags并指出`RCODE=3`。
5. **上游转发（60秒）**：查询公网域名，展示客户端到Relay、Relay到上游的两段UDP通信。
6. **协议字段（60秒）**：对比请求和响应的Transaction ID、QR、RD、RA、QDCOUNT和ANCOUNT。
7. **可靠性（30秒）**：展示上游超时或非法报文测试，说明程序不会卡死或崩溃。
8. **总结（30秒）**：展示测试通过数量、已知限制和三位成员分工。

演示时同时打开 Relay 日志、查询终端、Wireshark 和 `dnsrelay.txt`。日志至少打印时间、客户端、Transaction ID、域名、类型、处理分支、上游地址、耗时和结果，但不要直接打印不可读的完整二进制报文。

## 9. 报告与验收材料

课程报告建议按以下结构编写：课程目标；开发环境；成员分工；总体架构；Socket API流程；DNS报文设计；三个核心处理分支；并发与异常处理；测试环境和测试矩阵；Wireshark分析；问题与解决过程；限制和可选改进；总结。

截图应标注关键字段，而不是只放终端结果。至少准备四张证据图：TCP收发、本地A记录、NXDOMAIN、上游转发。验收表中的“程序概述”要明确填写语言、环境、实现功能及测试情况，成员职责必须与报告一致。

## 10. 实施里程碑

- [ ] M1：Python 版本、默认端口和演示上游已确定；三位成员分工待填写。
- [x] M2：完成TCP Client-Server并验证连续收发。
- [x] M3：完成DNS Header与Question解析单元测试。
- [x] M4：完成本地A记录与NXDOMAIN响应。
- [x] M5：完成上游转发、超时和并发隔离。
- [x] M6：19 项自动测试已通过；抓包按安排延期到另一台电脑采集。
- [x] M7：报告和演示说明已完成；成员信息按实际分工填入原验收记录。
- [ ] M8：在一台干净机器上按README重新运行全部演示。

完成标准不是“程序能够启动”，而是三个核心分支均有正确结果、报文字段经Wireshark验证、异常输入不会导致进程崩溃，并且第三方能按照README复现。
