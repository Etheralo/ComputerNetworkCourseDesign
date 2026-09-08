# Wireshark 证据清单

此目录应保存课程验收所需的抓包文件或截图。当前目录中的
`dig_verification.txt` 只是脱敏的文本验证，**不是 Wireshark 抓包，不能替代
`.pcapng` 或截图**。

## Windows 抓包前准备

1. 安装 Wireshark，并确保安装了 Npcap。
2. 按课件要求以管理员身份启动 Wireshark。
3. 本地 Relay 使用 `127.0.0.1:5353`，请选择 **Npcap Loopback Adapter**。
4. 上游转发还会经过 Wi-Fi 或以太网网卡。抓上游案例时同时选择 Loopback
   Adapter 和当前联网网卡；如果版本不支持多网卡同时捕获，就分别抓两次。
5. 5353 是非标准 DNS 端口，捕获后在 Wireshark 中选择
   **Analyze -> Decode As...**，将 UDP 5353 解码为 DNS。

推荐显示过滤器：

```text
dns && (udp.port == 5353 || udp.port == 53)
```

如果 `dns` 过滤器暂时匹配不到 5353 端口的数据，先使用：

```text
udp.port == 5353 || udp.port == 53
```

完成 `Decode As... -> DNS` 后再使用前一个过滤器。

## 最少需要的证据

- `tcp_socket_demo.pcapng`：Loopback 上 TCP 9000 的连续收发、`exit` 和 FIN/ACK。
- `dns_local_a.pcapng`：Loopback 上 `local.test A` 的请求和本地 A Answer。
- `dns_nxdomain.pcapng`：Loopback 上 `blocked.test A` 的 `RCODE=3`、`ANCOUNT=0`。
- `dns_upstream.pcapng`：客户端到 Relay、Relay 到上游 DNS 的两段 UDP 通信。

也应保存对应截图，截图中展开并标注：

- Transaction ID；
- `QR`、`RD`、`RA`、`RCODE`；
- `QDCOUNT`、`ANCOUNT`；
- 本地 A 响应中的 `TYPE=A`、`CLASS=IN`、`TTL` 和 IPv4 地址。

## Windows 查询命令

如果系统没有 `dig`，在项目根目录打开 PowerShell：

```powershell
py -3 -m src.dns_relay.query --name local.test --type A
py -3 -m src.dns_relay.query --name blocked.test --type A
py -3 -m src.dns_relay.query --name www.baidu.com --type A
```

查询上游案例时，若公网 UDP/53 被防火墙拦截，可使用
`Get-DnsClientServerAddress -AddressFamily IPv4` 找到本机实际 DNS，
再以 `--upstream <地址>` 启动 Relay。不要把上游地址设置为 Relay 自己。

抓包完成后只保留本实验相关的包，避免提交私人 DNS 流量。
