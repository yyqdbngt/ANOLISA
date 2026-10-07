#!/usr/bin/env python3
"""Tests for generate_image.py network resilience.

Regression tests for task polling: a transient network error between two
poll iterations (or one failed request) used to escape _wanx as an
uncaught URLError and kill the script after the task had already been
submitted, losing an image the task would have delivered.
"""

import importlib.util
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(SCRIPTS_DIR, "generate_image.py")


def load_module():
    spec = importlib.util.spec_from_file_location("generate_image", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def readable(self):
        return True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class WanxPollResilience(unittest.TestCase):
    def test_transient_poll_error_does_not_kill_a_running_task(self):
        # Submit succeeds; the first poll request dies with a transport
        # error (connection reset); the second reports SUCCEEDED. The
        # task exists and will finish — the poll loop must ride over the
        # transient error instead of crashing the whole script.
        module = load_module()
        submit = FakeResponse({"output": {"task_id": "tid-1"}})
        succeeded = FakeResponse(
            {
                "output": {
                    "task_status": "SUCCEEDED",
                    "results": [{"url": "https://example.test/img.png"}],
                }
            }
        )
        script = [
            submit,
            urllib.error.URLError("connection reset by peer"),
            succeeded,
        ]
        index = {"i": 0}

        def fake_urlopen(req, timeout=None):
            step = script[index["i"]]
            index["i"] += 1
            if isinstance(step, Exception):
                raise step
            return step

        with mock.patch("time.sleep"), mock.patch.object(
            module.urllib.request, "urlopen", side_effect=fake_urlopen
        ):
            url = module._wanx("a prompt", "wanx2.1-t2i-turbo", "1024*1024", "key")

        self.assertEqual(url, "https://example.test/img.png")

    def test_submit_transport_failure_exits_with_a_clean_error(self):
        # A refused connection (proxy down, DNS failure) used to escape as
        # an uncaught URLError traceback; the CLI contract is a clean
        # ERROR line and exit status 1.
        module = load_module()

        def fake_urlopen(req, timeout=None):
            raise urllib.error.URLError("[Errno 61] Connection refused")

        with mock.patch.object(
            module.urllib.request, "urlopen", side_effect=fake_urlopen
        ):
            with self.assertRaises(SystemExit) as caught:
                module._wanx("a prompt", "wanx2.1-t2i-turbo", "1024*1024", "key")

        self.assertEqual(caught.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
