#!/usr/bin/env python3
"""Exercise QMP capabilities and an ordered savevm/loadvm round trip."""

from __future__ import annotations

import argparse
import json
import math
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any

MAX_QMP_MESSAGE_BYTES = 1024 * 1024
MAX_RECORDED_EVENT_NAMES = 256


class QmpError(RuntimeError):
    pass


class QmpClient:
    def __init__(self, socket_path: Path, timeout: float) -> None:
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        self._socket.connect(str(socket_path))
        self._reader = self._socket.makefile("rb")
        self._timeout = timeout
        self._next_id = 1
        self.events: list[str] = []

    def close(self) -> None:
        self._reader.close()
        self._socket.close()

    def receive(self, deadline: float, waiting_for: str) -> dict[str, Any]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise QmpError(f"timed out waiting for {waiting_for}")
        self._socket.settimeout(remaining)
        try:
            line = self._reader.readline(MAX_QMP_MESSAGE_BYTES + 1)
        except TimeoutError as exc:
            raise QmpError(f"timed out waiting for {waiting_for}") from exc
        if not line:
            raise QmpError("QMP peer closed the connection")
        if len(line) > MAX_QMP_MESSAGE_BYTES:
            raise QmpError("QMP message exceeds 1048576 bytes")
        if not line.endswith(b"\n"):
            raise QmpError("QMP message is not newline terminated")
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QmpError(f"invalid QMP JSON: {exc}") from exc
        if not isinstance(message, dict):
            raise QmpError("QMP message is not a JSON object")
        return message

    def negotiate(self) -> None:
        greeting = self.receive(self._new_deadline(), "QMP greeting")
        self._validate_greeting(greeting)
        result = self.execute("qmp_capabilities")
        if not isinstance(result, dict):
            raise QmpError("qmp_capabilities return value is not an object")

    def execute(
        self, command: str, arguments: dict[str, Any] | None = None
    ) -> Any:
        command_id = f"fovea-{self._next_id}"
        self._next_id += 1
        request: dict[str, Any] = {"execute": command, "id": command_id}
        if arguments is not None:
            request["arguments"] = arguments
        payload = json.dumps(request, separators=(",", ":")).encode() + b"\r\n"
        self._socket.settimeout(self._timeout)
        self._socket.sendall(payload)
        reply = self._wait_for_reply(command_id, self._new_deadline())
        has_return = "return" in reply
        has_error = "error" in reply
        if has_return == has_error:
            raise QmpError(
                f"{command} reply must contain exactly one of return or error"
            )
        if has_error:
            error = reply["error"]
            if (
                not isinstance(error, dict)
                or not isinstance(error.get("class"), str)
                or not isinstance(error.get("desc"), str)
            ):
                raise QmpError(f"{command} reply contains a malformed error")
            raise QmpError(
                f"{command} failed: "
                f"{json.dumps(error, sort_keys=True, separators=(',', ':'))}"
            )
        return reply["return"]

    def _new_deadline(self) -> float:
        return time.monotonic() + self._timeout

    def _wait_for_reply(
        self, command_id: str, deadline: float
    ) -> dict[str, Any]:
        while True:
            message = self.receive(deadline, f"QMP reply id {command_id}")
            if "event" in message:
                event_name = self._validate_event(message)
                if len(self.events) < MAX_RECORDED_EVENT_NAMES:
                    self.events.append(event_name)
                continue
            if "id" not in message:
                raise QmpError("unexpected QMP message without event or id")
            reply_id = message["id"]
            if not isinstance(reply_id, str):
                raise QmpError("QMP reply id is not a string")
            if reply_id != command_id:
                raise QmpError(
                    f"unexpected QMP reply id: {reply_id}; "
                    f"expected {command_id}"
                )
            return message

    @staticmethod
    def _validate_greeting(greeting: dict[str, Any]) -> None:
        qmp = greeting.get("QMP")
        if not isinstance(qmp, dict):
            raise QmpError("missing or malformed QMP greeting")
        version = qmp.get("version")
        capabilities = qmp.get("capabilities")
        if not isinstance(version, dict) or not isinstance(capabilities, list):
            raise QmpError("malformed QMP greeting metadata")
        qemu = version.get("qemu")
        package = version.get("package")
        if not isinstance(qemu, dict) or not isinstance(package, str):
            raise QmpError("malformed QMP version")
        for field in ("major", "minor", "micro"):
            value = qemu.get(field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise QmpError(f"malformed QMP version field: {field}")
        if not all(isinstance(capability, str) for capability in capabilities):
            raise QmpError("malformed QMP capabilities list")

    @staticmethod
    def _validate_event(message: dict[str, Any]) -> str:
        event_name = message["event"]
        if not isinstance(event_name, str):
            raise QmpError("QMP event name is not a string")
        if "id" in message or "return" in message or "error" in message:
            raise QmpError("QMP event contains reply fields")
        if "data" in message and not isinstance(message["data"], dict):
            raise QmpError("QMP event data is not an object")
        if "timestamp" in message and not isinstance(message["timestamp"], dict):
            raise QmpError("QMP event timestamp is not an object")
        return event_name


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise argparse.ArgumentTypeError("must be in the range 0 < timeout <= 3600")
    return timeout


def snapshot_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        raise argparse.ArgumentTypeError(
            "must be 1..64 characters using letters, digits, '.', '_' or '-'"
        )
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Negotiate QMP, then save and restore one named snapshot."
    )
    parser.add_argument("--socket", required=True, type=Path, help="QMP Unix socket")
    parser.add_argument(
        "--snapshot",
        required=True,
        type=snapshot_name,
        help="explicit snapshot name",
    )
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=10.0,
        help="connect and complete greeting/reply timeout in seconds (default: 10)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client: QmpClient | None = None
    save_command = f"savevm {args.snapshot}"
    load_command = f"loadvm {args.snapshot}"
    try:
        client = QmpClient(args.socket, args.timeout)
        client.negotiate()
        save_result = client.execute(
            "human-monitor-command", {"command-line": save_command}
        )
        if not isinstance(save_result, str):
            raise QmpError("savevm return value is not a string")
        if save_result.strip():
            raise QmpError(
                f"savevm returned diagnostic output: {save_result.strip()}"
            )
        load_result = client.execute(
            "human-monitor-command", {"command-line": load_command}
        )
        if not isinstance(load_result, str):
            raise QmpError("loadvm return value is not a string")
        if load_result.strip():
            raise QmpError(
                f"loadvm returned diagnostic output: {load_result.strip()}"
            )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "snapshot": args.snapshot,
                    "commands": [
                        "qmp_capabilities",
                        save_command,
                        load_command,
                    ],
                    "events_seen": client.events,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, QmpError) as exc:
        print(f"qmp-smoke: {exc}", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
