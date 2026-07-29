#!/usr/bin/env python3
"""Contract tests for the M0 QMP smoke client."""

from __future__ import annotations

import errno
import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


SCRIPT = Path(__file__).resolve().parent.parent / "qmp-smoke.py"
SPEC = importlib.util.spec_from_file_location("fovea_qmp_smoke", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load qmp-smoke.py")
QMP_SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QMP_SMOKE)

JsonObject = Dict[str, Any]
Session = Callable[[socket.socket, List[JsonObject]], None]


def json_line(message: JsonObject) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"


def greeting() -> JsonObject:
    return {
        "QMP": {
            "version": {
                "qemu": {"major": 8, "minor": 2, "micro": 1},
                "package": "fovea-test",
            },
            "capabilities": ["oob"],
        }
    }


def padded_line(message: JsonObject, total_bytes: int) -> bytes:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    padding = total_bytes - len(payload) - 1
    if padding < 0:
        raise ValueError("message does not fit requested line size")
    return payload + (b" " * padding) + b"\n"


def receive_request(reader: Any) -> JsonObject:
    line = reader.readline()
    if not line:
        raise EOFError("client closed before sending expected request")
    request = json.loads(line)
    if not isinstance(request, dict):
        raise AssertionError("request is not a JSON object")
    return request


def scripted_session(
    replies: List[List[bytes]], greeting_line: Optional[bytes] = None
) -> Session:
    def session(conn: socket.socket, requests: List[JsonObject]) -> None:
        conn.sendall(greeting_line or json_line(greeting()))
        reader = conn.makefile("rb")
        try:
            for response_frames in replies:
                request = receive_request(reader)
                requests.append(request)
                for frame in response_frames:
                    conn.sendall(frame)
        finally:
            reader.close()

    return session


def standard_replies(
    save_result: str = "", load_result: str = ""
) -> List[List[bytes]]:
    return [
        [json_line({"return": {}, "id": "fovea-1"})],
        [json_line({"return": save_result, "id": "fovea-2"})],
        [json_line({"return": load_result, "id": "fovea-3"})],
    ]


class FakeQmpServer:
    def __init__(self, session: Session) -> None:
        self._tempdir = tempfile.TemporaryDirectory(
            prefix="fovea-qmp-", dir="/tmp"
        )
        self.path = Path(self._tempdir.name) / "qmp.sock"
        self.requests: List[JsonObject] = []
        self.error: Optional[BaseException] = None
        self._session = session
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "FakeQmpServer":
        self._thread.start()
        if not self._ready.wait(2.0):
            raise RuntimeError("fake QMP server did not become ready")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._thread.join(3.0)
        if self._thread.is_alive():
            raise AssertionError("fake QMP server did not terminate")
        self._tempdir.cleanup()
        if exc_type is None and self.error is not None:
            raise AssertionError("fake QMP server failed") from self.error

    def _run(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            listener.listen(1)
            listener.settimeout(2.0)
            self._ready.set()
            conn, _ = listener.accept()
            try:
                conn.settimeout(2.0)
                self._session(conn, self.requests)
            except OSError as exc:
                if exc.errno not in (
                    errno.EPIPE,
                    errno.ECONNRESET,
                    errno.EBADF,
                ):
                    raise
            finally:
                conn.close()
        except BaseException as exc:
            self.error = exc
            self._ready.set()
        finally:
            listener.close()


class QmpSmokeContractTests(unittest.TestCase):
    maxDiff = None

    def run_cli(
        self,
        session: Session,
        timeout: str = "1",
        snapshot: str = "contract-snap",
    ) -> Tuple[subprocess.CompletedProcess[str], List[JsonObject]]:
        with FakeQmpServer(session) as server:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--socket",
                    str(server.path),
                    "--snapshot",
                    snapshot,
                    "--timeout",
                    timeout,
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=4.0,
                check=False,
            )
            requests = list(server.requests)
        return result, requests

    def assert_failed_with(
        self, result: subprocess.CompletedProcess[str], text: str
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn(text, result.stderr)

    def test_structured_greeting_order_ids_and_async_events(self) -> None:
        event_one = {
            "event": "RESET",
            "data": {"guest": True},
            "timestamp": {"seconds": 1, "microseconds": 2},
        }
        event_two = {"event": "STOP", "data": {}}
        replies = [
            [
                json_line(event_one),
                json_line({"return": {}, "id": "fovea-1"}),
            ],
            [
                json_line(event_two),
                json_line({"return": "", "id": "fovea-2"}),
            ],
            [json_line({"return": " \t", "id": "fovea-3"})],
        ]

        result, requests = self.run_cli(
            scripted_session(replies), snapshot="snap.with-spaces-safe"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            requests,
            [
                {"execute": "qmp_capabilities", "id": "fovea-1"},
                {
                    "execute": "human-monitor-command",
                    "id": "fovea-2",
                    "arguments": {
                        "command-line": "savevm snap.with-spaces-safe"
                    },
                },
                {
                    "execute": "human-monitor-command",
                    "id": "fovea-3",
                    "arguments": {
                        "command-line": "loadvm snap.with-spaces-safe"
                    },
                },
            ],
        )
        self.assertEqual(
            json.loads(result.stdout),
            {
                "status": "ok",
                "snapshot": "snap.with-spaces-safe",
                "commands": [
                    "qmp_capabilities",
                    "savevm snap.with-spaces-safe",
                    "loadvm snap.with-spaces-safe",
                ],
                "events_seen": ["RESET", "STOP"],
            },
        )

    def test_malformed_greeting_is_rejected(self) -> None:
        bad_greeting = {
            "QMP": {
                "version": {
                    "qemu": {"major": True, "minor": 2, "micro": 1},
                    "package": "fake",
                },
                "capabilities": [],
            }
        }
        result, requests = self.run_cli(
            scripted_session([], json_line(bad_greeting))
        )
        self.assert_failed_with(result, "malformed QMP version field: major")
        self.assertEqual(requests, [])

    def test_malformed_json_reply_is_rejected(self) -> None:
        result, requests = self.run_cli(
            scripted_session([[b"{not-json}\n"]])
        )
        self.assert_failed_with(result, "invalid QMP JSON")
        self.assertEqual(
            requests, [{"execute": "qmp_capabilities", "id": "fovea-1"}]
        )

    def test_structured_error_reply_is_rejected(self) -> None:
        replies = [
            [json_line({"return": {}, "id": "fovea-1"})],
            [
                json_line(
                    {
                        "error": {
                            "class": "GenericError",
                            "desc": "snapshot backend refused",
                        },
                        "id": "fovea-2",
                    }
                )
            ],
        ]
        result, requests = self.run_cli(scripted_session(replies))
        self.assert_failed_with(
            result,
            'human-monitor-command failed: {"class":"GenericError",'
            '"desc":"snapshot backend refused"}',
        )
        self.assertEqual(len(requests), 2)

    def test_unexpected_reply_id_is_rejected(self) -> None:
        replies = [[json_line({"return": {}, "id": "foreign-id"})]]
        result, requests = self.run_cli(scripted_session(replies))
        self.assert_failed_with(
            result,
            "unexpected QMP reply id: foreign-id; expected fovea-1",
        )
        self.assertEqual(len(requests), 1)

    def test_nonempty_savevm_diagnostic_is_rejected(self) -> None:
        replies = standard_replies(save_result="Device is not snapshotable")
        result, requests = self.run_cli(scripted_session(replies[:2]))
        self.assert_failed_with(
            result,
            "savevm returned diagnostic output: Device is not snapshotable",
        )
        self.assertEqual(len(requests), 2)

    def test_nonempty_loadvm_diagnostic_is_rejected(self) -> None:
        replies = standard_replies(load_result="Snapshot does not exist")
        result, requests = self.run_cli(scripted_session(replies))
        self.assert_failed_with(
            result,
            "loadvm returned diagnostic output: Snapshot does not exist",
        )
        self.assertEqual(len(requests), 3)

    def test_message_at_exact_limit_is_accepted(self) -> None:
        greeting_line = padded_line(
            greeting(), QMP_SMOKE.MAX_QMP_MESSAGE_BYTES
        )
        result, requests = self.run_cli(
            scripted_session(standard_replies(), greeting_line)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(requests), 3)

    def test_message_above_limit_is_rejected(self) -> None:
        greeting_line = padded_line(
            greeting(), QMP_SMOKE.MAX_QMP_MESSAGE_BYTES + 1
        )
        result, requests = self.run_cli(scripted_session([], greeting_line))
        self.assert_failed_with(
            result, "QMP message exceeds 1048576 bytes"
        )
        self.assertEqual(requests, [])

    def test_sustained_event_flood_hits_deadline_with_bounded_names(self) -> None:
        def flood_session(
            conn: socket.socket, requests: List[JsonObject]
        ) -> None:
            conn.sendall(json_line(greeting()))
            reader = conn.makefile("rb")
            try:
                requests.append(receive_request(reader))
                event = json_line({"event": "FLOOD", "data": {}})
                while True:
                    conn.sendall(event)
            finally:
                reader.close()

        timeout = 0.20
        with FakeQmpServer(flood_session) as server:
            client = QMP_SMOKE.QmpClient(server.path, timeout)
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(
                    QMP_SMOKE.QmpError,
                    "timed out waiting for QMP reply id fovea-1",
                ):
                    client.negotiate()
            finally:
                elapsed = time.monotonic() - started
                retained_events = list(client.events)
                client.close()
            requests = list(server.requests)

        self.assertGreaterEqual(elapsed, timeout * 0.70)
        self.assertLess(elapsed, 1.5)
        self.assertEqual(len(retained_events), 256)
        self.assertEqual(set(retained_events), {"FLOOD"})
        self.assertEqual(
            requests, [{"execute": "qmp_capabilities", "id": "fovea-1"}]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
