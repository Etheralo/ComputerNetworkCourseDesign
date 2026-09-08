"""Interactive or scripted TCP client for the course demonstration."""

from __future__ import annotations

import argparse
import socket


def exchange(host: str, port: int, messages: list[str] | None = None) -> None:
    with socket.create_connection((host, port), timeout=5) as connection:
        with connection.makefile("rwb") as stream:
            print(f"已连接 {host}:{port}，输入 exit 结束")
            scripted = iter(messages) if messages is not None else None
            while True:
                if scripted is None:
                    try:
                        message = input("> ")
                    except EOFError:
                        message = "exit"
                else:
                    try:
                        message = next(scripted)
                    except StopIteration:
                        message = "exit"
                    print(f"> {message}")
                stream.write((message + "\n").encode("utf-8"))
                stream.flush()
                reply = stream.readline()
                if not reply:
                    raise ConnectionError("服务端在回复前关闭连接")
                print(reply.decode("utf-8").rstrip())
                if message.strip().lower() == "exit":
                    return


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP Socket 演示客户端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        "--message", action="append", dest="messages", help="脚本消息，可重复"
    )
    args = parser.parse_args()
    exchange(args.host, args.port, args.messages)


if __name__ == "__main__":
    main()
