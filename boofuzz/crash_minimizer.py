import os
import re

import attr

from . import exception, helpers

# Failure signatures produced by CrashMinimizer.replay(). The signature describes
# the *kind* of failure (its "fingerprint"), independent of which message in the
# sequence triggered it, so that minimized sequences can be compared against the
# original failure.
SIGNATURE_CONNECT_FAILED = "connect-failed"
SIGNATURE_SEND_RESET = "connection-reset-on-send"
SIGNATURE_RECV_RESET = "connection-reset-on-recv"
SIGNATURE_NO_RESPONSE = "no-response"

_CONNECTION_ERRORS = (
    exception.BoofuzzTargetConnectionReset,
    exception.BoofuzzTargetConnectionAborted,
)


@attr.s
class MinimizedCrash:
    """Result of minimizing a crashing test case.

    Attributes:
        test_case_name (str): Name of the original test case.
        original_messages (list of bytes): Message sequence originally sent to the target.
        minimized_messages (list of bytes): Smallest message sequence found that still
            reproduces the same failure signature.
        failure_signature (str): Failure signature reproduced by the minimized sequence.
        verified (bool): True if the minimized sequence was replayed and reproduced the
            same failure signature on every verification round.
        export_path (str): Directory the minimized sequence was exported to, if any.
    """

    test_case_name = attr.ib(type=str, default="")
    original_messages = attr.ib(factory=list)
    minimized_messages = attr.ib(factory=list)
    failure_signature = attr.ib(type=str, default="")
    verified = attr.ib(type=bool, default=False)
    export_path = attr.ib(type=str, default=None)

    @property
    def original_size(self):
        """Total size in bytes of the original message sequence."""
        return sum(len(m) for m in self.original_messages)

    @property
    def minimized_size(self):
        """Total size in bytes of the minimized message sequence."""
        return sum(len(m) for m in self.minimized_messages)


class CrashMinimizer:
    """Replays and minimizes crashing message sequences against a live target.

    The minimizer re-sends a captured message sequence using fresh connections
    to confirm the failure stably reproduces, then greedily removes handshake
    (prefix) messages and irrelevant payload bytes while the same failure
    signature keeps reproducing. The resulting minimal sequence can be exported
    to disk for standalone reproduction.

    Args:
        connection_factory (callable): Zero-argument callable returning a fresh,
            unopened ITargetConnection to the target.
        fuzz_data_logger (IFuzzLogger): Optional logger for progress messages.
        verify_count (int): Number of times a sequence must reproduce the same
            failure signature to be considered stable. Default 1.
        export_dir (str): Optional directory to export minimized sequences to.
        max_replay_steps (int): Budget of replay attempts for minimization.
            Default 256.
        recv_bytes (int): Maximum bytes to receive per response. Default 10000.
    """

    def __init__(
        self,
        connection_factory,
        fuzz_data_logger=None,
        verify_count=1,
        export_dir=None,
        max_replay_steps=256,
        recv_bytes=10000,
    ):
        self._connection_factory = connection_factory
        self._logger = fuzz_data_logger
        self._verify_count = max(1, verify_count)
        self._export_dir = export_dir
        self._max_replay_steps = max_replay_steps
        self._recv_bytes = recv_bytes
        self._replay_count = 0

    def _log_info(self, description):
        if self._logger is not None:
            self._logger.log_info(description)

    def _log_pass(self, description):
        if self._logger is not None:
            self._logger.log_pass(description)

    def _log_fail(self, description):
        if self._logger is not None:
            self._logger.log_fail(description)

    def replay(self, messages):
        """Replay a message sequence against the target once.

        Args:
            messages (list of bytes): Messages to send in order. After each
                message the target's response is read.

        Returns:
            str: A failure signature if a failure was observed, None otherwise.
        """
        self._replay_count += 1
        connection = self._connection_factory()
        try:
            connection.open()
        except exception.BoofuzzTargetConnectionFailedError:
            return SIGNATURE_CONNECT_FAILED
        try:
            for message in messages:
                try:
                    connection.send(message)
                except _CONNECTION_ERRORS:
                    return SIGNATURE_SEND_RESET
                try:
                    data = connection.recv(self._recv_bytes)
                except _CONNECTION_ERRORS:
                    return SIGNATURE_RECV_RESET
                if not data:
                    return SIGNATURE_NO_RESPONSE
            return None
        finally:
            try:
                connection.close()
            except Exception:  # noqa: B902 -- closing a half-dead connection may raise anything
                pass

    def _reproduces(self, messages, signature):
        """Check whether messages reproduce the given failure signature on every round."""
        for _ in range(self._verify_count):
            if self.replay(messages) != signature:
                return False
        return True

    @property
    def _budget_exhausted(self):
        return self._replay_count >= self._max_replay_steps

    def minimize(self, messages, test_case_name=""):
        """Confirm and minimize a failing message sequence.

        Args:
            messages (list of bytes): Message sequence that triggered a failure.
            test_case_name (str): Name of the originating test case (for logging/export).

        Returns:
            MinimizedCrash: The minimized, verified result, or None if the
            failure could not be stably reproduced.
        """
        messages = [bytes(m) for m in messages]
        self._replay_count = 0

        signature = self.replay(messages)
        if signature is None:
            self._log_info(
                "Crash minimization: original sequence of {0} message(s) did not reproduce a failure; "
                "skipping minimization.".format(len(messages))
            )
            return None
        if not self._reproduces(messages, signature):
            self._log_fail(
                "Crash minimization: failure signature '{0}' did not reproduce stably over {1} replay(s); "
                "skipping minimization.".format(signature, self._verify_count)
            )
            return None
        self._log_info(
            "Crash minimization: failure signature '{0}' confirmed for test case '{1}'.".format(
                signature, test_case_name
            )
        )

        original_messages = list(messages)
        minimized = self._minimize_sequence(messages, signature)
        minimized = self._minimize_bytes(minimized, signature)

        verified = self._reproduces(minimized, signature)
        result = MinimizedCrash(
            test_case_name=test_case_name,
            original_messages=original_messages,
            minimized_messages=minimized,
            failure_signature=signature,
            verified=verified,
        )
        if verified:
            self._log_pass(
                "Crash minimization: minimized from {0} message(s)/{1} byte(s) to "
                "{2} message(s)/{3} byte(s); signature '{4}' verified.".format(
                    len(original_messages),
                    result.original_size,
                    len(minimized),
                    result.minimized_size,
                    signature,
                )
            )
        else:
            self._log_fail("Crash minimization: minimized sequence did not verify stably.")

        if self._export_dir is not None:
            result.export_path = self._export(result)
            self._log_info("Crash minimization: minimized sequence exported to {0}".format(result.export_path))
        return result

    def _minimize_sequence(self, messages, signature):
        """Greedily drop whole messages (e.g. handshake steps) while the failure persists."""
        messages = list(messages)
        changed = True
        while changed and len(messages) > 1 and not self._budget_exhausted:
            changed = False
            for i in range(len(messages)):
                if len(messages) <= 1 or self._budget_exhausted:
                    break
                candidate = messages[:i] + messages[i + 1 :]
                if self._reproduces(candidate, signature):
                    self._log_info(
                        "Crash minimization: dropped message {0} ({1} byte(s)); failure still reproduces.".format(
                            i, len(messages[i])
                        )
                    )
                    messages = candidate
                    changed = True
                    break
        return messages

    def _minimize_bytes(self, messages, signature):
        """Greedily trim irrelevant bytes from each message while the failure persists."""
        messages = list(messages)
        # The final (fuzzed) message usually carries the most junk; trim it first.
        for index in reversed(range(len(messages))):
            if self._budget_exhausted:
                break
            message = messages[index]
            chunk = max(1, len(message) // 2)
            while chunk >= 1 and not self._budget_exhausted:
                offset = 0
                while offset < len(message) and not self._budget_exhausted:
                    candidate = message[:offset] + message[offset + chunk :]
                    if 0 < len(candidate) < len(message):
                        trial = list(messages)
                        trial[index] = candidate
                        if self._reproduces(trial, signature):
                            message = candidate
                            messages[index] = candidate
                            continue  # retry same offset; content shifted left
                    offset += chunk
                chunk //= 2
        return messages

    def _export(self, result):
        """Write the minimized sequence to disk and return the export directory."""
        export_dir = self._export_dir
        helpers.mkdir_safe(export_dir)
        base_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", result.test_case_name).strip("_")[:80] or "case"
        case_dir = os.path.join(export_dir, base_name)
        helpers.mkdir_safe(case_dir)

        for i, message in enumerate(result.minimized_messages):
            with open(os.path.join(case_dir, "msg-{0}.bin".format(i)), "wb") as f:
                f.write(message)

        summary_lines = [
            "Test case: {0}".format(result.test_case_name),
            "Failure signature: {0}".format(result.failure_signature),
            "Verified: {0}".format(result.verified),
            "Original: {0} message(s), {1} byte(s)".format(len(result.original_messages), result.original_size),
            "Minimized: {0} message(s), {1} byte(s)".format(len(result.minimized_messages), result.minimized_size),
            "",
            "Minimized message sequence:",
        ]
        for i, message in enumerate(result.minimized_messages):
            summary_lines.append("  msg-{0} ({1} bytes): {2!r}".format(i, len(message), message))
        with open(os.path.join(case_dir, "minimized.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(summary_lines) + "\n")
        return case_dir
