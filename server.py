#!/usr/bin/env python3
"""
server.py — Simple Multi-threaded TCP Server (Protected Service)
Listens on port 8080 and handles incoming client requests.
"""

import socket
import threading

HOST = "0.0.0.0"
PORT = 8080


def handle_client(conn, addr):
    """Handle an individual connected client."""
    print(f"[*] New connection from {addr[0]}:{addr[1]}")
    try:
        data = conn.recv(1024)
        if data:
            print(f"[*] Received from {addr[0]}: {data.decode().strip()}")
            # Send simple HTTP / application response
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello from Server!\n"
            conn.sendall(response)
    except Exception as e:
        print(f"[-] Error handling client {addr}: {e}")
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(100)
    print(f"[*] Server listening on {HOST}:{PORT}...")

    try:
        while True:
            conn, addr = server.accept()
            # Handle each connection in a separate thread
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
