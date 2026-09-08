import socket
import threading
import unittest

from src.socket_demo.server import serve_connection


class SocketDemoTests(unittest.TestCase):
    def test_multiple_messages_and_exit_close_cleanly(self):
        server_socket, client_socket = socket.socketpair()
        thread = threading.Thread(
            target=serve_connection, args=(server_socket, ("local", 0)), daemon=True
        )
        thread.start()
        with client_socket, client_socket.makefile("rwb") as stream:
            stream.write("你好\nsecond\nexit\n".encode("utf-8"))
            stream.flush()
            self.assertEqual(stream.readline().decode("utf-8"), "ACK: 你好\n")
            self.assertEqual(stream.readline().decode("utf-8"), "ACK: second\n")
            self.assertEqual(stream.readline().decode("utf-8"), "BYE\n")
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
