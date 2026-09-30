import argparse
import socket
import struct
import sys
import threading

import des

NAME = "Receiver"

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
    ap = argparse.ArgumentParser(description="Receiver (server) - DES manual")
    ap.add_argument("--bind", default="0.0.0.0", help="alamat bind (default semua interface)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", required=True, help="key DES, tepat 8 karakter")
    a = ap.parse_args()
    key = a.key.encode()
    if len(key) != 8:
        sys.exit("Key DES wajib tepat 8 karakter")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port))
    srv.listen(1)
    print(f"[{NAME}] Menunggu Sender di port {a.port} ...")
    sock, addr = srv.accept()
    print(f"[{NAME}] Sender terhubung dari {addr}")

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
    srv.close()


if __name__ == "__main__":
    main()