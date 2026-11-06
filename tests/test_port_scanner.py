import socket
import threading

import pytest

from port_scanner import parse_ports, scan


def test_parse_ports_handles_lists_and_ranges():
    assert parse_ports("22, 80,8000-8002,80") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_rejects_out_of_range():
    with pytest.raises(ValueError):
        parse_ports("0,70000")


def test_scan_finds_local_listener_and_banner():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-TestServer\r\n")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    closed = parse_ports("1")  # port 1 is almost never open locally
    results = scan("127.0.0.1", [port] + closed, timeout=1, banner=True)
    server.close()
    assert [r.port for r in results] == [port]
    assert results[0].banner == "SSH-2.0-TestServer"
