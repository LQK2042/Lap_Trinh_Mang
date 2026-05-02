# NETWORK PROGRAMMING 
## WEEK 1 — LAB EXERCISE SHEETS

| | |
|---|---|
| **Course:** Network Programming with AI/ML for Cybersecurity | **Duration:** 3 hours guided lab (Lab 1: 90 min · Lab 2: 90 min) |
| **Week:** 1 of 7.5 | **Level:** Beginner–Intermediate |

These lab sheets accompany Week 1 theory sessions on TCP/UDP socket programming, blocking vs non-blocking I/O, and asynchronous networking with Python's `asyncio`. Students complete both labs in sequence. Each lab builds directly on the preceding one.

---

## Week 1 Overview

**Theme:** Raw sockets to async I/O — the plumbing before the intelligence

| Block | Content |
|---|---|
| Theory (2 hrs) | TCP/UDP fundamentals, socket lifecycle, blocking vs non-blocking, asyncio event loop, aiohttp basics |
| Lab 1 (90 min) | Multi-client TCP Chat Server using standard sockets + threading |
| Lab 2 (90 min) | Asynchronous Port Scanner using asyncio — scan 1,000 ports concurrently |

---

## Learning Objectives

| # | Objective |
|---|---|
| **1** | Understand the TCP/IP socket lifecycle: `socket()` → `bind()` → `listen()` → `accept()` → `send/recv` → `close()` |
| **2** | Implement a multi-client TCP server using Python's `socket` and `threading` modules |
| **3** | Explain the difference between blocking, non-blocking, and asynchronous I/O models |
| **4** | Use `asyncio` and `asyncio.open_connection()` to build concurrent network clients |
| **5** | Measure and compare throughput and concurrency between threaded and async approaches |
| **6** | Identify real-world cybersecurity applications of socket-level network programming |

---

## Prerequisites & Setup

Before starting these labs, ensure you have the following installed:

- Python 3.10 or higher (`python3 --version`)
- No external packages required for Lab 1 (uses standard library only)
- No external packages required for Lab 2 (uses `asyncio` from standard library)
- A terminal / VS Code with Python extension
- Two terminal windows open side-by-side (one for server, one for client)

> **NOTE:** All labs run on localhost (`127.0.0.1`). No external network access is required. If you are on Windows, use WSL2 or Git Bash for a consistent terminal experience.

---

---

# LAB 1 — Multi-Client TCP Chat Server

| **Duration:** 90 minutes | **Difficulty:** Beginner | **Format:** Individual | **Submission:** `chat_server.py` |
|---|---|---|---|

## Overview

In this lab you will build a TCP chat server that accepts multiple simultaneous clients. Each connected client can broadcast a message to all other connected clients. This is a foundational pattern used in intrusion detection alert brokers, SIEM event streams, and C2 (command-and-control) communication channels studied in offensive security.

> **SECURITY CONTEXT:** Understanding raw TCP socket programming is essential for network forensics: packet capture analysis, protocol reverse engineering, and building custom honeypot listeners all rely on exactly these primitives.

## Background Reading

Review the following concepts before starting (covered in theory session):

- TCP three-way handshake: SYN → SYN-ACK → ACK
- Python socket API: `socket.socket(AF_INET, SOCK_STREAM)`
- Server socket lifecycle: `socket()` → `bind()` → `listen()` → `accept()`
- Client socket lifecycle: `socket()` → `connect()` → `send/recv`
- Blocking I/O: `accept()` and `recv()` block the thread until data arrives
- `threading.Thread`: spawning a new OS thread per connected client

---

### Task 1: Create the Server Skeleton ⏱ 15 min

Create a new file called `chat_server.py`. Begin with the server skeleton below. Read every line carefully — comments explain each system call.

```python
# chat_server.py — Week 1 Lab 1 Skeleton

import socket
import threading

HOST = '127.0.0.1'   # Loopback interface — localhost only
PORT = 9000           # Choose any port above 1024 (unprivileged)
MAX_CLIENTS = 10      # Maximum pending connections in the backlog queue

# Global list to track all active client connections
clients = []          # Each entry: (conn_socket, client_address)
clients_lock = threading.Lock()  # Protect shared list from race conditions

def start_server():
    # AF_INET  = IPv4 address family
    # SOCK_STREAM = TCP (connection-oriented, reliable, ordered)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # SO_REUSEADDR lets us restart the server without waiting for TIME_WAIT
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_sock.bind((HOST, PORT))   # Bind to address:port
    server_sock.listen(MAX_CLIENTS)  # Start listening; backlog = MAX_CLIENTS
    print(f'[SERVER] Listening on {HOST}:{PORT}')

    while True:
        # accept() BLOCKS until a client connects
        # Returns: (new_socket_for_this_client, (client_ip, client_port))
        conn, addr = server_sock.accept()
        print(f'[CONNECT] New client from {addr}')

        # --- YOUR CODE HERE ---
        # 1. Add (conn, addr) to the clients list (use the lock!)
        # 2. Spawn a new thread to handle this client
        # 3. Set thread as daemon so it dies when the main thread exits
        # ----------------------

if __name__ == '__main__':
    start_server()
```

---

### Task 2: Implement the Client Handler ⏱ 25 min

Add the `handle_client()` function above `start_server()`. This function runs in its own thread for each connected client.

```python
def handle_client(conn, addr):
    """
    Receives messages from one client and broadcasts to all others.
    Runs in a dedicated thread per connection.
    """
    nickname = None
    try:
        # Step 1: Ask the new client to set a nickname
        conn.sendall(b'Enter your nickname: ')
        nickname = conn.recv(1024).decode('utf-8').strip()
        print(f'[NICKNAME] {addr} chose nickname: {nickname}')

        # Announce new user to all existing clients
        broadcast(f'[SERVER] {nickname} has joined the chat!', sender=conn)

        # Step 2: Enter the message receive loop
        while True:
            # recv() BLOCKS until data arrives or connection closes
            # 4096 = buffer size in bytes (tune for your use case)
            data = conn.recv(4096)
            if not data:
                # Empty bytes = client closed the connection gracefully
                break

            message = data.decode('utf-8').strip()

            # --- YOUR CODE HERE ---
            # Format the message with nickname prefix
            # e.g. '[Alice] Hello everyone!'
            # Call broadcast() to send to all other clients
            # Print the message on the server console too
            # ----------------------

    except ConnectionResetError:
        # Client forcibly closed the connection (e.g. Ctrl+C on client side)
        print(f'[DISCONNECT] {addr} disconnected abruptly')

    finally:
        # Always clean up: remove from list and close socket
        with clients_lock:
            clients[:] = [(c, a) for c, a in clients if c != conn]
        conn.close()
        if nickname:
            broadcast(f'[SERVER] {nickname} has left the chat.', sender=None)
        print(f'[CLOSED] Connection to {addr} closed')
```

---

### Task 3: Implement the `broadcast()` Function ⏱ 15 min

The broadcast function sends a message to every connected client except the sender. This is the core logic of a chat server (and also how SIEM alert distribution works).

```python
def broadcast(message: str, sender=None):
    """
    Send message to all connected clients except the sender.

    Args:
        message: UTF-8 string to broadcast
        sender:  socket of the originating client (excluded from broadcast)
                 Pass None to broadcast to ALL clients (e.g. server announcements)
    """
    encoded = (message + '\n').encode('utf-8')

    # --- YOUR CODE HERE ---
    # 1. Acquire the clients_lock
    # 2. Iterate over all (conn, addr) in clients
    # 3. Skip the sender socket
    # 4. Use conn.sendall(encoded) — sendall retries on partial sends
    # 5. Handle exceptions: if a client is broken, remove it from the list
    # ----------------------

    pass
```

---

### Task 4: Build the Client Script ⏱ 15 min

Create a second file `chat_client.py`. This client runs in two threads: one to receive incoming messages and one to read from stdin and send.

```python
# chat_client.py — Week 1 Lab 1

import socket
import threading

HOST = '127.0.0.1'
PORT = 9000

def receive_messages(sock):
    """Background thread: print incoming messages from the server."""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print('[DISCONNECTED] Server closed the connection.')
                break
            print(data.decode('utf-8'), end='')
        except:
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f'[CONNECTED] to {HOST}:{PORT}')

    # Start background thread to print received messages
    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()

    # Main thread: read input from user and send to server
    try:
        while True:
            msg = input()          # Blocks until user presses Enter
            if msg.lower() == '/quit':
                break
            sock.sendall(msg.encode('utf-8'))
    finally:
        sock.close()

if __name__ == '__main__':
    main()
```

---

### Task 5: Test & Observe ⏱ 20 min

Follow these steps to test your chat server with multiple simultaneous clients:

1. Open **Terminal 1**. Start the server: `python3 chat_server.py`
2. Open **Terminal 2**. Start client A: `python3 chat_client.py` → Enter nickname **Alice**
3. Open **Terminal 3**. Start client B: `python3 chat_client.py` → Enter nickname **Bob**
4. From Alice's terminal, type: `Hello Bob!` — verify Bob receives it.
5. From Bob's terminal, type: `Hey Alice!` — verify Alice receives it.

> **OBSERVE:** Watch the server terminal. Each connect/disconnect and each message should print a server-side log. This mirrors how a security event broker logs connections — your server terminal IS the SIEM console.

---

## Extension Challenges (if time permits)

- Add a `/list` command that returns the list of currently connected nicknames
- Add a `/pm <nickname> <message>` private message command
- Log all messages to a file `chat_log.txt` with timestamps
- Limit maximum message length to 256 bytes and send an error if exceeded
- Add a connection rate limiter: reject clients connecting more than 3 times per minute from the same IP

## Lab 1 Reflection Questions

Answer these questions in your lab notebook or in a comment block at the top of `chat_server.py`:

- **Q1:** What happens if you remove the `threading.Lock()` from the clients list? Why is this a problem?
- **Q2:** What is the difference between `send()` and `sendall()`? Which should you use and why?
- **Q3:** If 100 clients connect simultaneously, what resource is consumed per client? What is the scalability implication?
- **Q4:** How would an attacker abuse this server? Name two specific attacks (hint: think about the broadcast function).

## Lab 1 Grading

| Deliverable | Description | Points |
|---|---|---|
| `chat_server.py` | Complete server with `handle_client()` and `broadcast()` | **30 pts** |
| `chat_client.py` | Working client with send/receive threads | **20 pts** |
| Reflection answers | 4 questions answered in comments or lab notebook | **20 pts** |
| Extension (bonus) | At least 1 extension challenge implemented | **+10 pts** |

---

---

# LAB 2 — Async Port Scanner with asyncio

| **Duration:** 90 minutes | **Difficulty:** Intermediate | **Format:** Individual | **Submission:** `port_scanner.py` |
|---|---|---|---|

## Overview

In this lab you will build an asynchronous port scanner using Python's `asyncio` library. Instead of spawning one thread per port (which would require 1,000 threads for 1,000 ports), you will use a single-threaded event loop with coroutines. You will then compare performance between the threaded approach and the async approach empirically.

> **SECURITY CONTEXT:** Port scanning is the first step in network reconnaissance. Tools like Nmap use optimized async I/O under the hood. Understanding how to build one from scratch gives you insight into detection evasion, timing analysis, and firewall bypass — core concepts in both offensive and defensive network security.

## Key Concepts

Make sure you understand these terms before starting:

| Term | Meaning |
|---|---|
| **Coroutine** | A function defined with `async def` that can suspend execution with `await` without blocking the OS thread |
| **Event Loop** | The asyncio scheduler that runs coroutines, switches between them when they `await` I/O, and resumes them when I/O completes |
| **`asyncio.gather()`** | Runs multiple coroutines concurrently and returns all results when all are complete |
| **`asyncio.Semaphore`** | Limits the number of coroutines that can execute concurrently — essential to avoid overwhelming the target or triggering IDS |
| **`open_connection()`** | asyncio's async equivalent of `socket.connect()` — returns `(reader, writer)` stream objects |
| **`asyncio.wait_for()`** | Adds a timeout to any coroutine — if it exceeds the limit, raises `asyncio.TimeoutError` |

---

### Task 1: Build the Basic Async Scanner ⏱ 30 min

Create `port_scanner.py`. Start with this skeleton and fill in the marked sections.

```python
# port_scanner.py — Week 1 Lab 2

import asyncio
import time
from typing import List, Tuple

TARGET     = '127.0.0.1'   # Scan localhost only (ethical scanning)
START_PORT = 1
END_PORT   = 1000
TIMEOUT    = 0.5            # Seconds to wait for connection before marking port closed
CONCURRENCY = 200           # Max simultaneous connection attempts

async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore) -> Tuple[int, bool]:
    """
    Try to open a TCP connection to host:port.
    Returns (port, True) if open, (port, False) if closed/filtered.
    Uses semaphore to limit concurrency.
    """
    async with semaphore:   # Acquire slot; auto-release when block exits
        try:
            # asyncio.wait_for wraps the coroutine with a timeout
            # open_connection raises ConnectionRefusedError if port is closed
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TIMEOUT
            )

            # --- YOUR CODE HERE ---
            # Port is open!
            # Close the writer cleanly (writer.close() then await writer.wait_closed())
            # Return (port, True)
            # ----------------------

        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            return (port, False)   # Port closed or filtered

async def run_scan(host: str, start: int, end: int) -> List[int]:
    """
    Scan all ports from start to end concurrently.
    Returns a sorted list of open port numbers.
    """
    semaphore = asyncio.Semaphore(CONCURRENCY)

    # --- YOUR CODE HERE ---
    # 1. Create a list of scan_port() coroutines for every port in range
    # 2. Use asyncio.gather(*tasks) to run them all concurrently
    # 3. Filter results where is_open == True
    # 4. Return sorted list of open port numbers
    # ----------------------

    pass

async def main():
    print(f'[SCAN] Starting async port scan of {TARGET} ports {START_PORT}-{END_PORT}')
    print(f'[SCAN] Concurrency: {CONCURRENCY}  |  Timeout: {TIMEOUT}s per port')
    print('-' * 60)

    start_time = time.perf_counter()
    open_ports = await run_scan(TARGET, START_PORT, END_PORT)
    elapsed = time.perf_counter() - start_time

    print(f'[DONE] Scan completed in {elapsed:.2f} seconds')
    print(f'[OPEN PORTS] ({len(open_ports)} found):')
    for port in open_ports:
        print(f'  {port}/tcp  OPEN')

if __name__ == '__main__':
    asyncio.run(main())
```

---

### Task 2: Add Service Banner Grabbing ⏱ 20 min

Once a port is found open, attempt to read the service banner (the first bytes the service sends, which often reveals version information). This is a critical reconnaissance technique.

```python
async def grab_banner(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Connect to an open port and attempt to read the service banner.
    Many services (FTP, SMTP, SSH, HTTP) send a greeting on connect.
    Returns the banner string, or empty string if none received.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        try:
            # For HTTP services, we need to send a request first
            if port in (80, 8080, 443, 8000, 8443):
                writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
                await writer.drain()

            # --- YOUR CODE HERE ---
            # Read up to 1024 bytes with a 1-second timeout
            # Decode to string (use errors='ignore' to handle binary data)
            # Strip whitespace and return
            # Return empty string if no data received
            # ----------------------

        finally:
            writer.close()
            await writer.wait_closed()
    except Exception:
        return ''

# Modify main() to call grab_banner() on each open port and display results:
#
# PORT     STATE   BANNER
# 22/tcp   OPEN    SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
# 80/tcp   OPEN    HTTP/1.0 200 OK ... Server: Apache/2.4.57
# 3306/tcp OPEN    5.7.42-log ...
```

---

### Task 3: Performance Comparison Experiment ⏱ 25 min

Now build a threaded version of the same scanner and measure both against your async version.

```python
# threaded_scanner.py — for performance comparison only

import socket
import threading
import time
from queue import Queue

TARGET = '127.0.0.1'
THREAD_COUNT = 200     # Match async concurrency for fair comparison
TIMEOUT = 0.5

open_ports = []
lock = threading.Lock()

def scan_worker(port_queue: Queue):
    """Worker thread: scan ports from the queue until empty."""
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((TARGET, port))
            if result == 0:
                with lock:
                    open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()
            port_queue.task_done()

# --- YOUR CODE HERE ---
# 1. Populate a Queue with ports 1-1000
# 2. Spawn THREAD_COUNT threads each running scan_worker
# 3. Time the entire scan
# 4. Print results in the same format as the async scanner
# ----------------------
```

**Experiment Results Table** — Run each scanner 3 times and record results:

| Metric | Run 1 | Run 2 | Run 3 | Average |
|---|---|---|---|---|
| Async scanner — time (s) | | | | |
| Async scanner — open ports | | | | |
| Threaded scanner — time (s) | | | | |
| Threaded scanner — open ports | | | | |
| CPU usage — async (`top` %) | | | | |
| CPU usage — threaded (`top` %) | | | | |
| Memory — async (MB) | | | | |
| Memory — threaded (MB) | | | | |

---

### Task 4: Add Command-Line Arguments ⏱ 15 min

Make your scanner production-ready by adding argument parsing. This is how real tools like Nmap accept inputs.

```python
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description='Async TCP port scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 port_scanner.py --target 127.0.0.1 --start 1 --end 1000
  python3 port_scanner.py --target 192.168.1.1 --ports 22,80,443,3306,8080
  python3 port_scanner.py --target 127.0.0.1 --concurrency 500 --timeout 1.0
        '''
    )
    parser.add_argument('--target',      default='127.0.0.1', help='Target host (IP or hostname)')
    parser.add_argument('--start',        type=int, default=1,    help='Start port')
    parser.add_argument('--end',          type=int, default=1000, help='End port')
    parser.add_argument('--ports',        help='Comma-separated specific ports, e.g. 22,80,443')
    parser.add_argument('--concurrency',  type=int, default=200,  help='Max concurrent connections')
    parser.add_argument('--timeout',      type=float, default=0.5, help='Connection timeout in seconds')
    parser.add_argument('--banner',       action='store_true',    help='Grab service banners on open ports')
    parser.add_argument('--output',       help='Save results to file (JSON format)')
    return parser.parse_args()

# --- YOUR CODE HERE ---
# Integrate argparse into main() so all parameters come from CLI
# If --ports is given, parse it to a list and ignore --start/--end
# If --output is given, save results as JSON: {port: banner_or_'open'}
# ----------------------
```

---

## Extension Challenges (if time permits)

- Add UDP port scanning using `socket.SOCK_DGRAM` (note: UDP has no SYN/ACK — use ICMP unreachable detection)
- Add OS detection heuristics based on banner strings (e.g. OpenSSH version → likely Linux)
- Output results in Nmap-compatible XML format
- Add a `--rate` option that limits scans to N ports per second (stealth mode)
- Visualise open ports as an ASCII bar chart in the terminal

## Lab 2 Reflection Questions

- **Q1:** Why does the async scanner typically outperform the threaded one for I/O-bound tasks like port scanning?
- **Q2:** What is the role of `asyncio.Semaphore` and why is it important from a security/ethics standpoint?
- **Q3:** What are the limitations of a simple TCP connect scan? Name two techniques that can evade it.
- **Q4:** A SOC analyst sees thousands of SYN packets hitting their server. What tool might be responsible? What defense would you deploy?

## Lab 2 Grading

| Deliverable | Description | Points |
|---|---|---|
| `port_scanner.py` | Async scanner with banner grabbing and argparse | **30 pts** |
| `threaded_scanner.py` | Threaded scanner for comparison | **10 pts** |
| Results table | All 8 rows completed with measured values | **15 pts** |
| Reflection answers | 4 questions answered | **15 pts** |
| Extension (bonus) | At least 1 extension challenge | **+10 pts** |

---

> *Network Programming with AI/ML for Cybersecurity | Week 1 Lab Sheets*
