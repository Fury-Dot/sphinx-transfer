
import os
import time
import socket
import struct
from typing import Callable, Optional


def get_local_ip() -> str:
    """Returns the machine's local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def send_file_tcp(host: str, port: int, filename: str,
                  bundle_path: str, progress_cb: Optional[Callable[[float], None]] = None) -> float:
    """
    Sends an encrypted bundle from a FILE to host:port over TCP.
    """
    t0     = time.perf_counter()
    fname  = filename.encode()
    file_size = os.path.getsize(bundle_path)
    header = struct.pack(">I", len(fname)) + fname + struct.pack(">Q", file_size)

    with socket.create_connection((host, port), timeout=30) as s:
        s.sendall(header)
        sent, CHUNK = 0, 65536
        with open(bundle_path, "rb") as f:
            while sent < file_size:
                chunk = f.read(CHUNK)
                if not chunk: break
                s.sendall(chunk)
                sent += len(chunk)
                if progress_cb:
                    progress_cb(sent / file_size)

    return time.perf_counter() - t0


def receive_file_tcp(port: int, save_dir: str,
                     progress_cb: Optional[Callable[[float], None]] = None,
                     status_cb: Optional[Callable[[str], None]] = None) -> tuple[str, str, float]:
    """
    Listens for ONE incoming TCP connection and receives the bundle into a FILE.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    if status_cb:
        status_cb(f"Listening on port {port}…")

    conn, addr = srv.accept()
    if status_cb:
        status_cb(f"Connected from {addr[0]}")

    t0 = time.perf_counter()

    with conn:
        def recv_exact(n: int) -> bytes:
            buf = b""
            while len(buf) < n:
                chunk = conn.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("Connection closed prematurely.")
                buf += chunk
            return buf

        fname_len = struct.unpack(">I", recv_exact(4))[0]
        filename  = recv_exact(fname_len).decode()
        blen      = struct.unpack(">Q", recv_exact(8))[0]

        # Save with .enc extension
        base = os.path.basename(filename)
        out_name = base if base.endswith(".enc") else base + ".enc"
        out_path = os.path.join(save_dir, out_name)
        
        received = 0
        with open(out_path, "wb") as f:
            while received < blen:
                chunk = conn.recv(min(65536, blen - received))
                if not chunk:
                    raise ConnectionError("Connection dropped during transfer.")
                f.write(chunk)
                received += len(chunk)
                if progress_cb:
                    progress_cb(received / blen)

    srv.close()
    return out_path, filename, time.perf_counter() - t0