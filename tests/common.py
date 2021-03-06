# stdlib
import inspect
import logging
import os
import signal
import sys
import traceback
import unittest

# project
from checks import AgentCheck
from config import get_checksd_path
from util import get_os, get_hostname

log = logging.getLogger('tests')

def get_check_class(name):
    checksd_path = get_checksd_path(get_os())
    if checksd_path not in sys.path:
        sys.path.append(checksd_path)

    check_module = __import__(name)
    check_class = None
    classes = inspect.getmembers(check_module, inspect.isclass)
    for _, clsmember in classes:
        if clsmember == AgentCheck:
            continue
        if issubclass(clsmember, AgentCheck):
            check_class = clsmember
            if AgentCheck in clsmember.__bases__:
                continue
            else:
                break

    return check_class

def load_check(name, config, agentConfig):
    checksd_path = get_checksd_path(get_os())
    if checksd_path not in sys.path:
        sys.path.append(checksd_path)

    check_module = __import__(name)
    check_class = None
    classes = inspect.getmembers(check_module, inspect.isclass)
    for _, clsmember in classes:
        if clsmember == AgentCheck:
            continue
        if issubclass(clsmember, AgentCheck):
            check_class = clsmember
            if AgentCheck in clsmember.__bases__:
                continue
            else:
                break
    if check_class is None:
        raise Exception("Unable to import check %s. Missing a class that inherits AgentCheck" % name)

    init_config = config.get('init_config', {})
    instances = config.get('instances')
    agentConfig['checksd_hostname'] = get_hostname(agentConfig)

    # init the check class
    try:
        return check_class(name, init_config=init_config, agentConfig=agentConfig, instances=instances)
    except Exception as e:
        raise Exception("Check is using old API, {0}".format(e))

def kill_subprocess(process_obj):
    try:
        process_obj.terminate()
    except AttributeError:
        # py < 2.6 doesn't support process.terminate()
        if get_os() == 'windows':
            import ctypes
            PROCESS_TERMINATE = 1
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False,
                process_obj.pid)
            ctypes.windll.kernel32.TerminateProcess(handle, -1)
            ctypes.windll.kernel32.CloseHandle(handle)
        else:
            os.kill(process_obj.pid, signal.SIGKILL)

def get_check(name, config_str):
    checksd_path = get_checksd_path(get_os())
    if checksd_path not in sys.path:
        sys.path.append(checksd_path)
    check_module = __import__(name)
    check_class = None
    classes = inspect.getmembers(check_module, inspect.isclass)
    for name, clsmember in classes:
        if AgentCheck in clsmember.__bases__:
            check_class = clsmember
            break
    if check_class is None:
        raise Exception("Unable to import check %s. Missing a class that inherits AgentCheck" % name)

    agentConfig = {
        'version': '0.1',
        'api_key': 'tota'
    }

    return check_class.from_yaml(yaml_text=config_str, check_name=name,
        agentConfig=agentConfig)

def read_data_from_file(filename):
    return open(os.path.join(os.path.dirname(__file__), 'data', filename)).read()


class AgentCheckTest(unittest.TestCase):
    DEFAULT_AGENT_CONFIG = {
        'version': '0.1',
        'api_key': 'toto'
    }

    def __init__(self, *args, **kwargs):
        super(AgentCheckTest, self).__init__(*args, **kwargs)

        if not hasattr(self, 'CHECK_NAME'):
            raise Exception("You must define CHECK_NAME")

        self.check = None

    def run_check(self, config, agent_config=None, mocks=None):
        agent_config = agent_config or self.DEFAULT_AGENT_CONFIG

        # If not loaded already, do it!
        if self.check is None:
            self.check = load_check(self.CHECK_NAME, config, agent_config)

        if mocks is not None:
            for func_name, mock in mocks.iteritems():
                if not hasattr(self.check, func_name):
                    continue
                else:
                    setattr(self.check, func_name, mock)

        error = None
        for instance in self.check.instances:
            try:
                self.check.check(instance)
            except Exception, e:
                # Catch error before re-raising it to be able to get service_checks
                print "Exception {0} during check".format(e)
                print traceback.format_exc()
                error = e

        self.metrics = self.check.get_metrics()
        self.events = self.check.get_events()
        self.service_checks = self.check.get_service_checks()
        self.warnings = self.check.get_warnings()

        if error is not None:
            raise error

    def print_current_state(self):
        log.debug("""++++++++ CURRENT STATE ++++++++
METRICS
    {metrics}

EVENTS
    {events}

SERVICE CHECKS
    {sc}

WARNINGS
    {warnings}
++++++++++++++++++++++++++++""".format(
            metrics=self.metrics,
            events=self.events,
            sc=self.service_checks,
            warnings=self.warnings
        ))

    def coverage_report(self):
        total_metrics = len(self.metrics)
        tested_metrics = 0
        untested_metrics = []
        for m in self.metrics:
            if m[3].get('tested'):
                tested_metrics += 1
            else:
                untested_metrics.append(m)
        if total_metrics == 0:
            coverage_metrics = 100.0
        else:
            coverage_metrics = 100.0 * tested_metrics / total_metrics

        total_sc = len(self.service_checks)
        tested_sc = 0
        untested_sc = []
        for sc in self.service_checks:
            if sc.get('tested'):
                tested_sc += 1
            else:
                untested_sc.append(sc)

        if total_sc == 0:
            coverage_sc = 100.0
        else:
            coverage_sc = 100.0 * tested_sc / total_sc

        coverage = """Coverage
========================================
    METRICS
        Tested {tested_metrics}/{total_metrics} ({coverage_metrics}%)
        UNTESTED: {untested_metrics}

    SERVICE CHECKS
        Tested {tested_sc}/{total_sc} ({coverage_sc}%)
        UNTESTED: {untested_sc}
========================================"""
        log.info(coverage.format(
            tested_metrics=tested_metrics,
            total_metrics=total_metrics,
            coverage_metrics=coverage_metrics,
            untested_metrics=untested_metrics,
            tested_sc=tested_sc,
            total_sc=total_sc,
            coverage_sc=coverage_sc,
            untested_sc=untested_sc,
        ))

        if os.getenv('COVERAGE'):
            self.assertEquals(coverage_metrics, 100.0)
            self.assertEquals(coverage_sc, 100.0)

    def _candidates_size_assert(self, candidates, count=None, at_least=1):
        try:
            if count is not None:
                self.assertEquals(len(candidates), count,
                    "Needed exactly %d candidates, got %d" % (count, len(candidates))
                )
            else:
                self.assertTrue(len(candidates) >= at_least,
                    "Needed at least %d candidates, got %d" % (at_least, len(candidates))
                )
        except AssertionError:
            self.print_current_state()
            raise

    def assertMetric(self, metric_name, value=None, tags=None, count=None, at_least=1):
        log.debug("Looking for metric {0}".format(metric_name))
        if value is not None:
            log.debug(" * with value {0}".format(value))
        if tags is not None:
            log.debug(" * tagged with {0}".format(tags))
        if count is not None:
            log.debug(" * should have exactly {0} data points".format(count))
        if at_least is not None:
            log.debug(" * should have at least {0} data points".format(at_least))

        candidates = []
        for m_name, ts, val, mdata in self.metrics:
            if m_name == metric_name:
                if value is not None and val != value:
                    continue
                if tags is not None and sorted(tags) != sorted(mdata.get("tags", [])):
                    continue

                candidates.append((m_name, ts, val, mdata))

        self._candidates_size_assert(candidates, count=count, at_least=at_least)
        for mtuple in self.metrics:
            for cmtuple in candidates:
                if mtuple == cmtuple:
                    mtuple[3]['tested'] = True
        log.debug("FOUND !")

    def assertMetricTagPrefix(self, metric_name, tag_prefix, count=None, at_least=1):
        log.debug("Looking for a tag starting with `{0}:` on metric {1}".format(tag_prefix, metric_name))
        if count is not None:
            log.debug(" * should have exactly {0} data points".format(count))
        if at_least is not None:
            log.debug(" * should have at least {0} data points".format(at_least))

        candidates = []
        for m_name, ts, val, mdata in self.metrics:
            if m_name == metric_name:
                gtags = [t for t in mdata['tags'] if t.startswith(tag_prefix)]
                if not gtags:
                    continue
                candidates.append((m_name, ts, val, mdata))

        self._candidates_size_assert(candidates, count=count)
        for mtuple in self.metrics:
            for cmtuple in candidates:
                if mtuple == cmtuple:
                    mtuple[3]['tested'] = True
        log.debug("FOUND !")

    def assertMetricTag(self, metric_name, tag, count=None, at_least=1):
        log.debug("Looking for tag {0} on metric {1}".format(tag, metric_name))
        if count is not None:
            log.debug(" * should have exactly {0} data points".format(count))
        if at_least is not None:
            log.debug(" * should have at least {0} data points".format(at_least))

        candidates = []
        for m_name, ts, val, mdata in self.metrics:
            if m_name == metric_name:
                gtags = [t for t in mdata['tags'] if t == tag]
                if not gtags:
                    continue
                candidates.append((m_name, ts, val, mdata))

        self._candidates_size_assert(candidates, count=count)
        for mtuple in self.metrics:
            for cmtuple in candidates:
                if mtuple == cmtuple:
                    mtuple[3]['tested'] = True
        log.debug("FOUND !")

    def assertServiceCheck(self, service_check_name, status=None, tags=None, count=None, at_least=1):
        log.debug("Looking for service check {0}".format(service_check_name))
        if status is not None:
            log.debug(" * with status {0}".format(status))
        if tags is not None:
            log.debug(" * tagged with {0}".format(tags))
        if count is not None:
            log.debug(" * should have exactly {0} statuses".format(count))
        candidates = []
        for sc in self.service_checks:
            if sc['check'] == service_check_name:
                if status is not None and sc['status'] != status:
                    continue
                if tags is not None and sorted(tags) != sorted(sc.get("tags")):
                    continue

                candidates.append(sc)

        self._candidates_size_assert(candidates, count=count, at_least=at_least)
        for sc in self.service_checks:
            for csc in candidates:
                if sc == csc:
                    sc['tested'] = True
        log.debug("FOUND !")

    def assertIn(self, first, second):
        self.assertTrue(first in second, "{0} not in {1}".format(first, second))

    def assertNotIn(self, first, second):
        self.assertTrue(first not in second, "{0} in {1}".format(first, second))
