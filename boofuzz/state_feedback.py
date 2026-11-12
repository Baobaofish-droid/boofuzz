import collections
import hashlib

import attr


def default_state_classifier(data):
    """Default response classifier: group responses by their SHA-1 digest.

    Args:
        data (bytes): Raw response data received from the target.

    Returns:
        str: Hashable state key.
    """
    return hashlib.sha1(bytes(data)).hexdigest()


@attr.s
class StateObservation:
    """Result of observing one target response.

    Attributes:
        state_id (int): Stable numeric identifier of the observed state (1-based, in order of discovery).
        is_new (bool): True if this state had never been observed before in this session.
        num_states (int): Total number of distinct states discovered so far (including this one).
        label (str): Human readable label for the state.
        key: The classifier key that identifies the state.
    """

    state_id = attr.ib(type=int)
    is_new = attr.ib(type=bool)
    num_states = attr.ib(type=int)
    label = attr.ib(type=str)
    key = attr.ib(default=None)


class ResponseStateTracker:
    """Tracks distinct response states observed from the fuzz target.

    After each test case, the response received from the target is classified
    (by default via a content hash, or via a user supplied ``classifier``
    callable) and mapped to a state. The tracker records when each state was
    first discovered so the session can report state exploration progress and
    react to newly discovered states.

    Args:
        classifier (callable): Optional callable mapping response bytes to a
            hashable state key. Defaults to :func:`default_state_classifier`.
    """

    def __init__(self, classifier=None):
        self._classifier = classifier if classifier is not None else default_state_classifier
        self._states = {}  # maps classifier key -> state_id
        self.history = []  # list of (test_case_index, state_id, is_new)

    def observe(self, data, test_case_index=None):
        """Classify a target response and record the observation.

        Args:
            data (bytes): Response data received from the target (may be None).
            test_case_index (int): Optional index of the test case that produced the response.

        Returns:
            StateObservation: Observation describing the (possibly new) state.
        """
        if data is None:
            data = b""
        key = self._classifier(bytes(data))
        is_new = key not in self._states
        if is_new:
            self._states[key] = len(self._states) + 1
        state_id = self._states[key]
        self.history.append((test_case_index, state_id, is_new))
        return StateObservation(
            state_id=state_id,
            is_new=is_new,
            num_states=len(self._states),
            label="state-{0}".format(state_id),
            key=key,
        )

    @property
    def num_states(self):
        """Total number of distinct states discovered so far."""
        return len(self._states)

    @property
    def new_state_count(self):
        """Number of observations that discovered a previously unseen state."""
        return sum(1 for _, _, is_new in self.history if is_new)

    @property
    def observation_count(self):
        """Total number of recorded observations."""
        return len(self.history)

    def summary(self):
        """Return a human readable summary of state exploration progress."""
        lines = [
            "State exploration summary: {0} distinct state(s) observed over {1} test case(s).".format(
                self.num_states, self.observation_count
            )
        ]
        for key, state_id in sorted(self._states.items(), key=lambda item: item[1]):
            lines.append("  state-{0}: {1}".format(state_id, str(key)[:64]))
        return "\n".join(lines)


class FeedbackCaseIterator:
    """Wraps a fuzz case iterator and allows injecting priority test cases.

    Behaves like the wrapped iterator, except that test cases injected via
    :meth:`inject` (e.g. deeper combinatorial cases for a path that just
    revealed a new response state) are yielded before the base iterator
    continues. This lets the session dynamically adjust scheduling based on
    runtime feedback without changing the underlying case generators.
    """

    def __init__(self, base_iterator):
        self._base = iter(base_iterator)
        self._injected = collections.deque()

    def __iter__(self):
        return self

    def __next__(self):
        while self._injected:
            try:
                return next(self._injected[0])
            except StopIteration:
                self._injected.popleft()
        return next(self._base)

    def inject(self, case_iterator):
        """Schedule cases from case_iterator to run before the base stream continues.

        Args:
            case_iterator (Iterable): Iterator of MutationContext objects.
        """
        self._injected.append(iter(case_iterator))

    @property
    def has_pending(self):
        """True if injected cases are still waiting to be executed."""
        return len(self._injected) > 0
