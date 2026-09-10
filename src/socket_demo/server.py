"""TCP server used to demonstrate connect, repeated I/O, and clean shutdown."""

from __future__ import annotations

import argparse
import socket


# 单个客户端会话：connection 是 accept 返回的通信 Socket，不是监听 Socket。
# 协议约定为 UTF-8 文本 + 换行；普通消息回复 ACK，exit 回复 BYE。
def serve_connection(connection: socket.socket, client: tuple[str, int]) -> None:
    print(f"客户端已连接: {client[0]}:{client[1]}")
    # makefile 将网络连接包装成二进制文件接口，并不写磁盘文件。
    # with 在正常返回或抛出异常时释放文件对象和连接。
    with connection, connection.makefile("rwb") as stream:
        while True:
            # TCP 没有消息边界，按换行读取一条消息；多读 1 字节用于判断超长。
            # 上限为含换行的 65536 字节，不是字符数；未配置服务端读取超时。
            raw_line = stream.readline(65537)
            if not raw_line:
                # EOF：对方关闭发送方向；空消息则是 b"\n"，不是 b""。
                print("客户端关闭连接")
                return
            if len(raw_line) > 65536 or not raw_line.endswith(b"\n"):
                stream.write("ERROR: 消息过长或缺少换行符\n".encode("utf-8"))
                stream.flush()
                return
            try:
                # 移除行尾 CR/LF，再把网络字节解码为字符串；保留正文空格。
                message = raw_line.rstrip(b"\r\n").decode("utf-8")
            except UnicodeDecodeError:
                stream.write("ERROR: 消息必须是 UTF-8\n".encode("utf-8"))
                stream.flush()
                return
            print(f"收到: {message}")
            # 退出指令忽略前后空格和大小写；先告别，再结束当前会话。
            if message.strip().lower() == "exit":
                stream.write("BYE\n".encode("utf-8"))
                stream.flush()
                print("会话正常结束")
                return
            # ACK 是应用层文本回复，不是 TCP 协议内部的确认报文。
            stream.write(f"ACK: {message}\n".encode("utf-8"))
            # 将文件缓冲数据交给 Socket，不代表对方已经处理完成。
            stream.flush()


def main() -> None:
    # host 是本机绑定地址：127.0.0.1 仅本机；0.0.0.0 监听所有 IPv4 接口。
    # port 为监听端口；once 表示处理一个客户端后退出整个服务端。
    parser = argparse.ArgumentParser(description="TCP Socket 演示服务端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--once", action="store_true", help="服务一个客户端后退出")
    args = parser.parse_args()

    # AF_INET 使用 IPv4；SOCK_STREAM 使用 TCP 字节流。
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # 地址复用有助于重启后重新绑定，不等于允许任意服务同时占用端口。
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen()
        print(f"TCP 服务端监听 {args.host}:{args.port}")
        while True:
            # accept 阻塞等待连接，返回通信 Socket 和客户端 (IP, 临时端口)。
            connection, client = server.accept()
            # 同步处理整个会话后才接受下一个：当前 TCP 程序不是并发服务端。
            serve_connection(connection, client)
            if args.once:
                break


if __name__ == "__main__":
    # 直接运行或 python -m 启动时执行；被测试导入时不启动监听。
    main()
