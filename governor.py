import copy
import heapq
import inspect

from collections import defaultdict


class LimiterConfigError(Exception):
    """
    Error when parsing limiter
    """
    pass


class Governor(object):
    _LIMITERS = []

    @classmethod
    def init(cls, config):
        cls._LIMITERS = LimiterParser.parse_limiters(config)

    def __init__(self, func=None, identifier=None):
        self._limiters = copy.deepcopy(self._LIMITERS)

    def set(self, func):
        """
        Set governor to run as a decorator
        """
        self._submit_metric = func
        self._submit_metric_arg_names = inspect.getargspec(func)[0]

    def get_status(self):
        """
        Returns limiter statuses and flush limiters
        """
        statuses = [l.get_status() for l in self._limiters]

        # Flush limiters
        self._limiters = copy.deepcopy(self._LIMITERS)

        return statuses

    def _name_args(self, arg_list, kwargs):
        """
        Name `arg_list` items and merge with `kwargs`
        """
        named_args = kwargs.copy()
        for i, arg_value in enumerate(arg_list):
            arg_name = self._submit_metric_arg_names[i + 1]
            named_args[arg_name] = arg_value
        return named_args

    def _check(self, args):
        """
        Check metric against all limiters.
        """
        return all(r.check(args) for r in self._limiters)

    def __call__(self, *args, **kw):
        """
        Decorator purpose around `submit_metric` method for 'real-time' analysis
        """
        # Shortcut when no rules are defined
        if not self._limiters:
            return self._submit_metric(*args, **kw)

        # Really dirty trick -> to improve
        named_args = self._name_args(args, kw)

        # Extract argument dict
        if self._check(named_args):
            return self._submit_metric(*args, **kw)


class LimiterParser(object):
    """
    Limiter parser
    """
    @staticmethod
    def parse_limiters(config):
        """
        Parse limiter config to limiters
        :param config: agent configuration
        :type config: dictionnary
        """
        # Process 'limit_contexts_by'
        limiters = [Limiter(r.get('scope'), r.get('selection'), r.get('limit'))
                    for r in config.get('limiters', [])]

        return limiters


class Limiter(object):
    """
    A generic limiter
    """
    _ATOMS = frozenset(['name', 'instance', 'check', 'tags'])

    def __init__(self, scope, selection, limit=None):
        # Definition
        self._scope, self._selection = self._make_scope_and_selection(scope, selection)
        self._limit_cardinal = limit or "inf"

        # Metric values extractor
        self._extract_metric_keys = self._extract_to_keys(self._scope, self._selection)

        # Limiter data structure
        self._active_selections_by_scope = defaultdict(ExpiringSelection)

        # Trace
        self._blocked_metrics = 0

    @classmethod
    def _make_scope_and_selection(cls, scope, selection):
        """
        Check limiter `scope` and `selection` settings. Cast as a tuple and returns.

        :param scope: scope where the rule applies
        :type scope: string tuple or singleton

        :param selection: selection where the rule applies
        :type selection: string tuple or singleton
        """
        if not scope or not selection:
            raise LimiterConfigError("Limiters must contain a `scope` and a `selection`.")

        scope = scope if isinstance(scope, tuple) else (scope,)
        selection = selection if isinstance(selection, tuple) else (selection,)

        for s in scope:
            if s not in cls._ATOMS:
                raise LimiterConfigError("Unrecognized {0} within `scope`. `scope` must"
                                         " be a subset of {1}".format(s, cls._ATOMS))
        for s in selection:
            if s not in cls._ATOMS:
                raise LimiterConfigError("Unrecognized {0} within `selection`. `selection` must"
                                         " be a subset of {1}".format(s, cls._ATOMS))

        return scope, selection

    @classmethod
    def _extract_to_keys(cls, scope, selection):
        """
        Returns a function that extracts scope and selection values from a metric

        :param scope: scope where the rule applies
        :type scope: string tuple or singleton

        :param selection: selection where the rule applies
        :type selection: string tuple or singleton
        """
        def get(d, k):
            """
            Returns hashable d.get(k)
            """
            v = d.get(k)
            if isinstance(v, list):
                v = tuple(v)
            return v

        return lambda x: (tuple(get(x, k) for k in scope), tuple(get(x, k) for k in selection))

    def check(self, *args, **kw):
        """
        Limiter main task.
        Check incoming metrics against the limit set, and returns a boolean

        :param *args: metric list parameters
        :param **kw: metric named parameters
        """
        scope_value, selection_value = self._extract_metric_keys(*args, **kw)

        active_scope_selections = self._active_selections_by_scope[scope_value]

        if selection_value in active_scope_selections:
            active_scope_selections.add(selection_value, 1)
            return True
        else:
            if len(active_scope_selections) >= self._limit_cardinal:
                self._blocked_metrics += 1
                return False
            active_scope_selections.add(selection_value, 1)
            return True

    def get_status(self):
        """
        Returns limiter trace:
        `scope_cardinal`            -> Number of scopes registred
        `blocked_metrics`           -> Number of blocked metrics
        `scope_overflow_cardinal`   -> Number of scope with selection overflows
        `max_selection_scope`       -> Scope with the maximum of selections registred
        `max_selection_cardinal`    -> Maximum number of selections registred for a scope
        """
        scope_cardinal = len(self._active_selections_by_scope)
        scope_overflow_cardinal = 0
        max_selection_scope = None
        max_selection_cardinal = 0

        for scope, selections in self._active_selections_by_scope.iteritems():
            if max_selection_cardinal < len(selections):
                max_selection_cardinal = len(selections)
                max_selection_scope = scope
            if len(selections) >= self._limit_cardinal:
                scope_overflow_cardinal += 1

        return {
            'definition': {
                'scope': self._scope,
                'selection': self._selection,
                'limit': self._limit_cardinal
            },
            'trace': {
                'scope_cardinal': scope_cardinal,
                'blocked_metrics': self._blocked_metrics,
                'scope_overflow_cardinal': scope_overflow_cardinal,
                'max_selection_scope': max_selection_scope,
                'max_selection_cardinal': max_selection_cardinal
            }
        }


class ExpiringSelection(object):
    """
    Store active selections
    """
    def __init__(self):
        self._timestamp_by_selection = {}   # Known selection
        self._selections_heap = []          # Iterate over selection in order of timestamps

    def __len__(self):
        """
        Returns unique not-expired selections cardinal
        """
        return len(self._timestamp_by_selection)

    def __contains__(self, selection):
        return selection in self._timestamp_by_selection

    def add(self, selection, timestamp):
        """
        Add selection
        """
        self._timestamp_by_selection[selection] = timestamp
        heapq.heappush(self._selections_heap, (timestamp, selection))

    def flush(self, max_timestamp):
        """
        Removes expired selections
        """
        while self._selections_heap and self._selections_heap[0][0] <= max_timestamp:
            expiry, key = heapq.heappop(self._selections_heap)
            if self._timestamp_by_selection.get(key) == expiry:
                del self._timestamp_by_selection[key]
