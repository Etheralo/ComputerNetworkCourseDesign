"""TCP server used to demonstrate connect, repeated I/O, and clean shutdown."""

from __future__ import annotations

import argparse
import socket


def serve_connection(connection: socket.socket, client: tuple[str, int]) -> None:
    print(f"客户端已连接: {client[0]}:{client[1]}")
    with connection, connection.makefile("rwb") as stream:
        while True:
            raw_line = stream.readline(65537)
            if not raw_line:
                print("客户端关闭连接")
                return
            if len(raw_line) > 65536 or not raw_line.endswith(b"\n"):
                stream.write("ERROR: 消息过长或缺少换行符\n".encode("utf-8"))
                stream.flush()
                return
            try:
                message = raw_line.rstrip(b"\r\n").decode("utf-8")
            except UnicodeDecodeError:
                stream.write("ERROR: 消息必须是 UTF-8\n".encode("utf-8"))
                stream.flush()
                return
            print(f"收到: {message}")
            if message.strip().lower() == "exit":
                stream.write("BYE\n".encode("utf-8"))
                stream.flush()
                print("会话正常结束")
                return
            stream.write(f"ACK: {message}\n".encode("utf-8"))
            stream.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP Socket 演示服务端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--once", action="store_true", help="服务一个客户端后退出")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen()
        print(f"TCP 服务端监听 {args.host}:{args.port}")
        while True:
            connection, client = server.accept()
            serve_connection(connection, client)
            if args.once:
                break


if __name__ == "__main__":
    main()
