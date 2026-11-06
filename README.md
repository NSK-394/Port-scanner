# Port Scanner

![tests](https://github.com/NSK-394/Port-scanner/actions/workflows/tests.yml/badge.svg)

A concurrent TCP connect scanner in pure Python (standard library only). It finds open ports, names the likely service, and can grab the banner a service sends on connect.

> **Legal:** only scan hosts you own or have explicit written permission to test.

## Features
- **Concurrent scanning**: `ThreadPoolExecutor` (100 threads by default) instead of one port at a time
- **Flexible port specs**: `22,80,443`, ranges like `1-1024`, or a built-in list of common ports
- **Service names** via the system services database (`socket.getservbyport`)
- **Banner grabbing** (`-b`) for services that announce themselves (SSH, FTP, SMTP)
- Resolves the hostname once and fails cleanly on bad hosts

## Usage
```bash
python port_scanner.py scanme.nmap.org              # common ports
python port_scanner.py 192.168.1.10 -p 1-1024 -b    # range + banners
python port_scanner.py localhost -p 22,80,8000-8100 -t 1 -w 200
```

```
Scanning scanme.nmap.org (17 ports)...
[open]    22/tcp  ssh  SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[open]    80/tcp  http
Done: 2 open
```

## How it works
A TCP connect scan completes the full three-way handshake (`connect_ex` returns 0 when the port is open). It's slower and noisier than a SYN scan, but it needs no root privileges or raw sockets. Each port is an I/O-bound task, so threads give a near-linear speedup until you hit the timeout floor.

## Limitations
- TCP connect scan only: no SYN/UDP scanning and no OS fingerprinting (use `nmap` for that)
- Service names come from the port number, not from protocol probing
- Filtered and closed ports both show up as "not open"

## Tests
```bash
pip install pytest && pytest -q
```
The tests start a real local listener and check that the scanner finds it and reads its banner.
