import argparse
import socket
import struct
import sys
import threading

import des

NAME = "Sender"


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup")
        buf += chunk
    return buf


def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, n)


def receive_loop(sock, key, stop):
    while not stop.is_set():
        try:
            frame = recv_frame(sock)
        except (ConnectionError, OSError):
            print(f"\n[{NAME}] Lawan bicara terputus.")
            stop.set()
            return
        print(f"\n[{NAME}] << ciphertext diterima : {frame.hex()}")
        try:
            print(f"[{NAME}] << plaintext hasil dekripsi: {des.decrypt(frame, key).decode('utf-8', 'replace')}")
        except ValueError as e:
            print(f"[{NAME}] !! Gagal dekripsi: {e}")


def main():
    ap = argparse.ArgumentParser(description="Sender (client) - DES manual")
    ap.add_argument("--host", required=True, help="IP/hostname Receiver")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", required=True, help="key DES, tepat 8 karakter")
    a = ap.parse_args()
    key = a.key.encode()
    if len(key) != 8:
        sys.exit("Key DES wajib tepat 8 karakter")

    sock = socket.socket()
    try:
        sock.connect((a.host, a.port))
    except OSError as e:
        sys.exit(f"[{NAME}] Gagal terhubung ke {a.host}:{a.port} -> {e}")
    print(f"[{NAME}] Terhubung ke Receiver {a.host}:{a.port}")

    stop = threading.Event()
    threading.Thread(target=receive_loop, args=(sock, key, stop), daemon=True).start()

    print(f"[{NAME}] Ketik pesan lalu Enter (/quit untuk keluar)")
    for line in sys.stdin:
        line = line.rstrip("\n")
        if stop.is_set() or line == "/quit":
            break
        if not line:
            continue
        ct = des.encrypt(line.encode("utf-8"), key)
        print(f"[{NAME}] >> plaintext : {line}")
        print(f"[{NAME}] >> ciphertext dikirim: {ct.hex()}")
        try:
            send_frame(sock, ct)
        except OSError:
            break
    stop.set()
    sock.close()


if __name__ == "__main__":
    main()