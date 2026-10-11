"""
Convenience launcher for the IDOR Virtual Lab.
Automatically detects port conflicts (such as Docker Desktop occupying port 5000)
and launches on an open port (defaulting to 5001 if 5000 is busy).
"""

import os
import sys
import socket
from app import create_app


def is_port_in_use(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def find_available_port(preferred_port=5000):
    if not is_port_in_use(preferred_port):
        return preferred_port
    for port in (5001, 5050, 8080, 8000):
        if not is_port_in_use(port):
            return port
    return preferred_port


if __name__ == "__main__":
    env_port = os.environ.get("PORT")
    if env_port:
        target_port = int(env_port)
    else:
        target_port = find_available_port(5000)

    host = "127.0.0.1"
    app = create_app()

    print(f"\n=======================================================")
    print(f" IDOR Virtual Lab - Broken Access Control Sandbox")
    print(f" Web Interface: http://{host}:{target_port}")
    if target_port != 5000:
        print(f" Note: Port 5000 was busy (e.g. com.docker.backend),")
        print(f" automatically bound to open port: {target_port}")
    print(f"=======================================================\n")

    app.run(host=host, port=target_port, debug=False)
