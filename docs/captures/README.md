# Wireshark 证据清单

此目录用于保存现场环境产生的抓包，不提交包含私人 DNS 流量的大型捕获文件。抓包前关闭无关网络程序，并只捕获本实验端口。

`dig_verification.txt` 是 2026-09-08 使用系统 `dig` 查询实际 Relay 得到的脱敏文本证据。它能独立验证本地 A、NXDOMAIN 和上游转发，但不是 pcap。当前决定暂不在本机抓包；后期换电脑时按下面的清单操作即可。

## 建议文件

- `tcp_socket_demo.pcapng`：TCP 9000 端口的连续收发与正常关闭。
- `dns_local_a.pcapng`：`local.test A` 的请求和本地 Answer。
- `dns_nxdomain.pcapng`：`blocked.test A` 的 NXDOMAIN 响应。
- `dns_upstream.pcapng`：公网域名查询的两段 UDP 通信。

Wireshark 显示过滤器：

```text
tcp.port == 9000
udp.port == 5353 || udp.port == 53
```

截图时展开 DNS Header 和 Answer，标注 Transaction ID、QR、RD、RA、RCODE、QDCOUNT、ANCOUNT。提交前检查捕获内容，只保留与实验有关的包。
