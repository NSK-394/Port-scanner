"""Concurrent TCP connect port scanner with basic service and banner detection.

Only scan hosts you own or have written permission to test.
"""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]


@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,8000-8010' into a sorted list of unique valid ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range 1-65535: {sorted(bad)[:5]}")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, timeout: float) -> str:
    """Read whatever the service sends first (SSH, FTP, SMTP announce themselves)."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(256)
    except OSError:
        return ""
    return data.decode(errors="replace").strip().splitlines()[0][:100] if data else ""


def scan_port(host: str, port: int, timeout: float = 0.5, banner: bool = False) -> PortResult | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
        text = grab_banner(sock, timeout) if banner else ""
        return PortResult(port, service_name(port), text)


def scan(host: str, ports: list[int], timeout: float = 0.5, workers: int = 100, banner: bool = False) -> list[PortResult]:
    ip = socket.gethostbyname(host)  # resolve once, fail fast on bad hostnames
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: scan_port(ip, p, timeout, banner), ports)
    return [r for r in results if r is not None]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Concurrent TCP connect port scanner")
    ap.add_argument("target", help="hostname or IP address")
    ap.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024 (default: common ports)")
    ap.add_argument("-t", "--timeout", type=float, default=0.5, help="per-port timeout in seconds")
    ap.add_argument("-w", "--workers", type=int, default=100, help="concurrent threads")
    ap.add_argument("-b", "--banner", action="store_true", help="try to read service banners")
    args = ap.parse_args(argv)

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    print(f"Scanning {args.target} ({len(ports)} ports)...")
    try:
        open_ports = scan(args.target, ports, args.timeout, args.workers, args.banner)
    except socket.gaierror:
        print(f"Could not resolve host: {args.target}")
        return 1
    for r in open_ports:
        line = f"[open] {r.port:>5}/tcp  {r.service}"
        print(f"{line}  {r.banner}" if r.banner else line)
    print(f"Done: {len(open_ports)} open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
