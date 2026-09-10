import socket
import threading
import unittest

from src.socket_demo.server import serve_connection


class SocketDemoTests(unittest.TestCase):
    def test_multiple_messages_and_exit_close_cleanly(self):
        # socketpair 创建本机互连 Socket，测试会话逻辑，不验证跨设备 TCP 握手。
        server_socket, client_socket = socket.socketpair()
        thread = threading.Thread(
            target=serve_connection, args=(server_socket, ("local", 0)), daemon=True
        )
        thread.start()
        with client_socket, client_socket.makefile("rwb") as stream:
            # 一次写入三行，验证服务端按消息边界逐条回复，并正确处理中文。
            stream.write("你好\nsecond\nexit\n".encode("utf-8"))
            stream.flush()
            self.assertEqual(stream.readline().decode("utf-8"), "ACK: 你好\n")
            self.assertEqual(stream.readline().decode("utf-8"), "ACK: second\n")
            self.assertEqual(stream.readline().decode("utf-8"), "BYE\n")
        thread.join(timeout=1)
        # 不仅检查 BYE 内容，还检查会话线程确实退出。
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
