"""Interactive or scripted TCP client for the course demonstration."""

from __future__ import annotations

import argparse
import socket


def exchange(host: str, port: int, messages: list[str] | None = None) -> None:
    # host/port 是服务端地址；本机出口 IP 和临时端口通常由操作系统选择。
    # 5 秒超时也影响连接后的阻塞网络操作，不限制 input 的键盘等待。
    with socket.create_connection((host, port), timeout=5) as connection:
        with connection.makefile("rwb") as stream:
            print(f"已连接 {host}:{port}，输入 exit 结束")
            # 未传 messages 时交互输入；传入列表时按顺序发送，便于脚本演示。
            scripted = iter(messages) if messages is not None else None
            while True:
                if scripted is None:
                    try:
                        message = input("> ")
                    except EOFError:
                        # 终端输入结束也走正常的 exit/BYE 流程。
                        message = "exit"
                else:
                    try:
                        message = next(scripted)
                    except StopIteration:
                        # 脚本列表耗尽后自动补发 exit，无需调用者手动添加。
                        message = "exit"
                    print(f"> {message}")
                # 应用层分帧：UTF-8 字节以换行结尾；同一连接反复收发。
                stream.write((message + "\n").encode("utf-8"))
                stream.flush()
                # 同步请求—响应：收到本轮回复后，才读取下一条用户输入。
                reply = stream.readline()
                if not reply:
                    raise ConnectionError("服务端在回复前关闭连接")
                print(reply.decode("utf-8").rstrip())
                if message.strip().lower() == "exit":
                    # 已读取告别响应；退出 with 时释放连接和缓冲文件对象。
                    return


def main() -> None:
    # 跨设备通信时，host 填服务端实际 IP，不能填 0.0.0.0 或本机回环地址。
    parser = argparse.ArgumentParser(description="TCP Socket 演示客户端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        # append 使多个 --message 汇集为列表；未提供时值为 None。
        "--message", action="append", dest="messages", help="脚本消息，可重复"
    )
    args = parser.parse_args()
    exchange(args.host, args.port, args.messages)


if __name__ == "__main__":
    # 模块命令入口；导入 exchange 不会自动发起连接。
    main()
