import os
import shutil
import socket
import struct
import tempfile
import threading
import time
import unittest

from boofuzz import (
    CrashMinimizer,
    IFuzzLogger,
    s_get,
    s_group,
    s_initialize,
    s_static,
    Session,
    Target,
    TCPSocketConnection,
)

THREAD_JOIN_TIMEOUT = 10


class StatefulProtocolServer:
    """Mock multi-state protocol server used to exercise feedback and minimization.

    Protocol (one command per recv, responses keep the connection open):
        HELO            -> "100-WELCOME"
        AUTH <token>    -> "200-AUTH-OK"
        EXEC <args>     -> "500-DEEP-OK" if args contain DEEP, else "300-EXEC-OK"
        anything else   -> "OK"
        payload containing CRASH -> connection is reset (simulates a service crash)
        payload containing HANG  -> no response is sent (simulates a hung service)
    """

    def __init__(self, host="127.0.0.1", hang_seconds=5.0):
        self.host = host
        self.hang_seconds = hang_seconds
        self.port = None
        self._server_socket = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, 0))
        self._server_socket.listen(16)
        self.port = self._server_socket.getsockname()[1]
        self._thread = threading.Thread(target=self._serve)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            self._server_socket.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(THREAD_JOIN_TIMEOUT)

    def _serve(self):
        self._server_socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            handler = threading.Thread(target=self._handle, args=(conn,))
            handler.daemon = True
            handler.start()

    @staticmethod
    def _reset_connection(conn):
        # Force a TCP RST by closing with a zero linger timeout.
        for fmt in ("ii", "hh"):
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(fmt, 1, 0))
                return
            except OSError:
                continue

    def _handle(self, conn):
        try:
            conn.settimeout(10)
            while not self._stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not data:
                    break
                if b"CRASH" in data:
                    self._reset_connection(conn)
                    break
                if b"HANG" in data:
                    time.sleep(self.hang_seconds)  # never respond; simulate hung service
                    break
                if data.startswith(b"HELO"):
                    conn.sendall(b"100-WELCOME\n")
                elif data.startswith(b"AUTH"):
                    conn.sendall(b"200-AUTH-OK\n")
                elif data.startswith(b"EXEC"):
                    if b"DEEP" in data:
                        conn.sendall(b"500-DEEP-OK\n")
                    else:
                        conn.sendall(b"300-EXEC-OK\n")
                else:
                    conn.sendall(b"OK\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class ListLogger(IFuzzLogger):
    """IFuzzLogger that records all log calls as (method, text) tuples."""

    def __init__(self):
        self.logs = []

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        pass

    def open_test_step(self, description):
        self.logs.append(("step", description))

    def log_send(self, data):
        pass

    def log_recv(self, data):
        pass

    def log_check(self, description):
        self.logs.append(("check", description))

    def log_pass(self, description=""):
        self.logs.append(("pass", description))

    def log_fail(self, description=""):
        self.logs.append(("fail", description))

    def log_info(self, description):
        self.logs.append(("info", description))

    def log_error(self, description):
        self.logs.append(("error", description))

    def close_test_case(self):
        pass

    def close_test(self):
        pass

    def texts(self, method=None):
        return [text for m, text in self.logs if method is None or m == method]


def _build_exec_session(server, name_prefix, logger, **kwargs):
    """Three-layer protocol graph: handshake -> auth -> exec (fuzzed)."""
    s_initialize(name_prefix + "-helo")
    s_static("HELO\r\n")

    s_initialize(name_prefix + "-auth")
    s_static("AUTH SECRET\r\n")

    s_initialize(name_prefix + "-exec")
    s_static("EXEC ")
    s_group(name_prefix + "-alpha", values=[b"ONE", b"TWO", b"DEEP"])
    s_static(" ")
    s_group(name_prefix + "-beta", values=[b"X", b"Y"])
    s_static("\r\n")

    session = Session(
        target=Target(connection=TCPSocketConnection(server.host, server.port, recv_timeout=2.0)),
        fuzz_loggers=[logger],
        receive_data_after_fuzz=True,
        web_port=None,
        **kwargs
    )
    session.connect(s_get(name_prefix + "-helo"))
    session.connect(s_get(name_prefix + "-helo"), s_get(name_prefix + "-auth"))
    session.connect(s_get(name_prefix + "-auth"), s_get(name_prefix + "-exec"))
    return session


class TestStateFeedback(unittest.TestCase):
    def setUp(self):
        self.server = StatefulProtocolServer()
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def test_new_response_states_are_tracked_and_logged(self):
        """
        Given: A session with state feedback enabled fuzzing the EXEC layer
        When:  Fuzzing reaches both the shallow and the deep server branch
        Then:  Both response states are discovered and progress is logged
        """
        logger = ListLogger()
        session = _build_exec_session(self.server, "fb", logger, enable_state_feedback=True)

        session.fuzz(max_depth=1)

        # alpha mutates to TWO/DEEP, beta mutates to Y (defaults are not re-fuzzed)
        self.assertEqual(3, session.num_cases_actually_fuzzed)
        # 300-EXEC-OK and 500-DEEP-OK
        self.assertEqual(2, session.state_tracker.num_states)
        self.assertEqual(2, session.state_tracker.new_state_count)
        self.assertEqual(3, session.state_tracker.observation_count)

        passes = logger.texts("pass")
        self.assertEqual(2, len([p for p in passes if "New response state discovered" in p]))
        self.assertIn("Response state feedback", logger.texts("step"))
        self.assertIn("2 distinct state(s)", session.state_exploration_summary())

    def test_feedback_escalation_schedules_deeper_cases(self):
        """
        Given: State feedback with escalation enabled
        When:  A new response state is discovered
        Then:  Deeper combinatorial cases for that path are dynamically scheduled
        """
        logger = ListLogger()
        session = _build_exec_session(
            self.server,
            "esc",
            logger,
            enable_state_feedback=True,
            feedback_escalate=True,
        )

        session.fuzz(max_depth=1)

        # 3 base cases + 2 escalated depth-2 combinations (alpha x beta mutations)
        self.assertEqual(5, session.num_cases_actually_fuzzed)
        self.assertEqual(2, session.state_tracker.num_states)
        escalations = [t for t in logger.texts("info") if "Escalating path" in t]
        self.assertTrue(any("combinatorial depth 2" in t for t in escalations))

    def test_state_feedback_disabled_by_default(self):
        """
        Given: A default session (no feedback options)
        When:  Fuzzing
        Then:  No state feedback is recorded or logged (backwards compatible)
        """
        logger = ListLogger()
        session = _build_exec_session(self.server, "off", logger)

        session.fuzz(max_depth=1)

        self.assertEqual(3, session.num_cases_actually_fuzzed)
        self.assertEqual(0, session.state_tracker.observation_count)
        self.assertNotIn("Response state feedback", logger.texts("step"))


class TestCrashMinimization(unittest.TestCase):
    def setUp(self):
        self.server = StatefulProtocolServer()
        self.server.start()
        self.export_dir = tempfile.mkdtemp(prefix="boofuzz-min-test-")

    def tearDown(self):
        self.server.stop()
        shutil.rmtree(self.export_dir, ignore_errors=True)

    def test_crash_is_replayed_minimized_and_exported(self):
        """
        Given: A session with crash minimization enabled and a payload that crashes the server
        When:  The crashing case is fuzzed
        Then:  The failure is replay-confirmed, the handshake and junk bytes are stripped,
               and the minimal reproducing sequence is exported
        """
        logger = ListLogger()

        s_initialize("min-helo")
        s_static("HELO\r\n")

        s_initialize("min-cmd")
        s_static("CMD ")
        s_group("min-payload", values=[b"PING", b"CRASH" + b"J" * 40])
        s_static("\r\n")

        session = Session(
            target=Target(connection=TCPSocketConnection(self.server.host, self.server.port, recv_timeout=2.0)),
            fuzz_loggers=[logger],
            check_data_received_each_request=True,
            receive_data_after_fuzz=True,
            minimize_crashes=True,
            minimized_crash_dir=self.export_dir,
            restart_sleep_time=0.1,
            web_port=None,
        )
        session.connect(s_get("min-helo"))
        session.connect(s_get("min-helo"), s_get("min-cmd"))

        session.fuzz(max_depth=1)

        self.assertEqual(1, session.num_cases_actually_fuzzed)
        self.assertEqual(1, len(session.minimized_crashes))

        result = list(session.minimized_crashes.values())[0]
        self.assertTrue(result.verified)
        self.assertEqual("connection-reset-on-recv", result.failure_signature)
        # original sequence: handshake + padded fuzz message
        self.assertEqual(2, len(result.original_messages))
        # minimized: handshake dropped, junk bytes stripped down to the crash trigger
        self.assertEqual(1, len(result.minimized_messages))
        self.assertEqual(b"CRASH", result.minimized_messages[0])
        self.assertLess(result.minimized_size, result.original_size)

        # exported artifacts
        self.assertIsNotNone(result.export_path)
        summary_file = os.path.join(result.export_path, "minimized.txt")
        bin_file = os.path.join(result.export_path, "msg-0.bin")
        self.assertTrue(os.path.isfile(summary_file))
        self.assertTrue(os.path.isfile(bin_file))
        with open(bin_file, "rb") as f:
            self.assertEqual(b"CRASH", f.read())
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = f.read()
        self.assertIn("connection-reset-on-recv", summary)
        self.assertIn("Verified: True", summary)

        # progress was logged through the regular fuzz logger interface
        self.assertIn("Crash replay and minimization", logger.texts("step"))
        self.assertTrue(any("minimized from" in t for t in logger.texts("pass")))

    def test_unreproducible_failure_is_not_minimized(self):
        """
        Given: A minimizer and a benign message sequence
        When:  minimize() is called
        Then:  No failure is found on replay and no result is produced
        """
        minimizer = CrashMinimizer(
            connection_factory=lambda: TCPSocketConnection(self.server.host, self.server.port, recv_timeout=0.5),
        )
        result = minimizer.minimize([b"HELO\r\n", b"EXEC ONE X\r\n"], test_case_name="benign")
        self.assertIsNone(result)

    def test_hang_timeout_signature_is_minimized(self):
        """
        Given: A server that hangs on HANG payloads
        When:  A hanging sequence is minimized
        Then:  The no-response signature is confirmed and the sequence reduced to the trigger
        """
        minimizer = CrashMinimizer(
            connection_factory=lambda: TCPSocketConnection(self.server.host, self.server.port, recv_timeout=0.2),
            verify_count=2,
        )
        messages = [b"HELO\r\n", b"CMD HANG" + b"Q" * 8 + b"\r\n"]
        result = minimizer.minimize(messages, test_case_name="hang-case")

        self.assertIsNotNone(result)
        self.assertTrue(result.verified)
        self.assertEqual("no-response", result.failure_signature)
        self.assertEqual(1, len(result.minimized_messages))
        self.assertEqual(b"HANG", result.minimized_messages[0])


if __name__ == "__main__":
    unittest.main()
