# DNS Relay 课程设计

本项目包含两个可直接运行的实验：TCP Client-Server 连续通信，以及带本地规则和上游转发的 UDP DNS Relay。实现仅使用 Python 标准库，适合在课堂现场展示 DNS 报文解析、Socket API、异常处理和有限并发。

## 最快验证

要求 Python 3.10+；当前代码已在 Python 3.13.5 验证。

```bash
make test       # 运行全部单元与本地端到端测试
make demo       # 使用内置伪上游，离线展示 DNS 三个核心分支
```

`make demo` 的预期结果包括：`local.test → 10.0.0.123`、`blocked.test → RCODE 3`、`public.example → 203.0.113.9`（由演示用伪上游返回）。它不会访问公网。

## TCP Socket 演示

打开两个终端，在终端 1 启动服务端：

```bash
make socket-server
```

在终端 2 启动客户端，连续输入消息，最后输入 `exit`：

```bash
make socket-client
```

也可脚本化运行客户端：

```bash
python3 -m src.socket_demo.client --message hello --message "DNS relay" --message exit
```

## 运行真实 DNS Relay

先确认一个真实且可达的上游 DNS，不要把上游指向 Relay 自己：

```bash
make run UPSTREAM=8.8.8.8
```

默认监听 `127.0.0.1:5353`，读取 [config/dnsrelay.txt](config/dnsrelay.txt)。另开终端查询：

```bash
dig @127.0.0.1 -p 5353 local.test A
dig @127.0.0.1 -p 5353 blocked.test A
dig @127.0.0.1 -p 5353 www.baidu.com A
dig @127.0.0.1 -p 5353 local.test AAAA
```

可直接查看全部参数：

```bash
python3 -m src.dns_relay.server --help
```

本地表每行格式为 `IPv4 域名`，支持 `#` 注释、大小写无关匹配和末尾点号。地址为 `0.0.0.0` 时返回 NXDOMAIN。

## 项目结构

- `src/dns_relay/`：DNS 编解码、本地表、并发 Relay 和离线演示。
- `src/socket_demo/`：TCP 服务端与客户端。
- `tests/`：19 项标准库 `unittest` 测试。
- `config/`：运行时本地域名表。
- `docs/`：设计、报告、展示步骤和抓包说明。

更完整的现场操作见 [展示与使用说明](docs/展示与使用说明.md)，实现与结论边界见 [课程设计报告](docs/report.md)。抓包暂不在本机执行，后期换电脑时直接按 [Wireshark 证据清单](docs/captures/README.md) 操作即可。

## 当前范围

Relay 支持单 Question 标准 DNS 请求，本地只生成 `A/IN` 答案；其他合法类型原样转发。未实现缓存、DNS over TCP、本地 IPv6 记录和 EDNS 专门处理。转发响应由连接式临时 UDP Socket 校验来源，并再次核对 Transaction ID；超时返回 SERVFAIL。
