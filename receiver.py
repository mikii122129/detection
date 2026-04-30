import argparse

from detection import DetectionEngine, LiveLogReceiver


def main() -> None:
    parser = argparse.ArgumentParser(description="Receive Apache access logs from a VM and run live OWASP detection.")
    parser.add_argument("--target-url", required=True, help="Base URL of the monitored application, for example http://192.168.56.101")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind on the receiver machine")
    parser.add_argument("--port", type=int, default=9999, help="TCP port used by sender.py")
    parser.add_argument("--save-file", default=None, help="Optional path for the saved raw traffic log on the host")
    args = parser.parse_args()

    detection_engine = DetectionEngine()
    receiver = LiveLogReceiver(
        detection_engine,
        args.target_url,
        host=args.host,
        port=args.port,
        log_output_path=args.save_file,
    )

    def on_progress(step: str, message: str) -> None:
        print(f"[{step}] {message}")

    def on_line(raw_line: str) -> None:
        print(f"[traffic] {raw_line}")

    def on_event(result) -> None:
        finding = result.get("finding")
        if not finding:
            return
        parsed = result["parsed"]
        print(
            f"[ALERT] {finding['severity'].upper()} {finding['owasp']} "
            f"{parsed.method} {parsed.request_target} from {parsed.remote_host} "
            f"status={parsed.status_code} confidence={finding['confidence']}%"
        )

    print(f"[file] saving received traffic to {receiver.log_output_path}")
    metrics = receiver.serve(
        progress_callback=on_progress,
        event_callback=on_event,
        line_callback=on_line,
    )
    print("[summary]", metrics)


if __name__ == "__main__":
    main()
