import argparse
import os
import socket
import time


def follow_file(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if line:
                yield line
            else:
                time.sleep(0.25)


def stream_log(path: str, host: str, port: int, reconnect_delay: float) -> None:
    while True:
        try:
            print(f"[sender] connecting to {host}:{port}")
            with socket.create_connection((host, port), timeout=10) as sock:
                print(f"[sender] connected, streaming {path}")
                for line in follow_file(path):
                    sock.sendall(line.encode("utf-8", errors="ignore"))
        except (OSError, ConnectionError) as exc:
            print(f"[sender] connection lost: {exc}. retrying in {reconnect_delay}s")
            time.sleep(reconnect_delay)


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream Apache access-log lines from the VM to the host detector.")
    parser.add_argument("--log-file", default="/var/log/apache2/access.log", help="Apache access log path on the VM")
    parser.add_argument("--host", required=True, help="Host machine IP address running receiver.py or the FastAPI live detector")
    parser.add_argument("--port", type=int, default=9999, help="Receiver TCP port")
    parser.add_argument("--reconnect-delay", type=float, default=2.0, help="Seconds to wait before reconnecting")
    args = parser.parse_args()

    if not os.path.exists(args.log_file):
        raise SystemExit(f"Log file not found: {args.log_file}")

    stream_log(args.log_file, args.host, args.port, args.reconnect_delay)


if __name__ == "__main__":
    main()
