from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


WORKER_MAIN = Path(__file__).resolve().parents[1] / "scanner-worker" / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("kryptscan_worker_main", WORKER_MAIN)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(worker)


class WorkerPlanTests(unittest.TestCase):
    def test_paid_service_levels_expand_the_tool_plan(self) -> None:
        standard = worker.ScanRequest(
            target="example.com",
            testing_context={"service_level": "standard"},
        )
        deep = worker.ScanRequest(
            target="example.com",
            testing_context={"service_level": "deep"},
        )
        pentest = worker.ScanRequest(
            target="example.com",
            assessment_mode="ethical_pentesting",
            testing_context={"service_level": "deep"},
        )

        standard_tools = {name for name, _, _ in worker._tool_plan("example.com", standard)}
        deep_tools = {name for name, _, _ in worker._tool_plan("example.com", deep)}
        pentest_tools = {name for name, _, _ in worker._tool_plan("example.com", pentest)}

        self.assertLess(standard_tools, deep_tools)
        self.assertLess(deep_tools, pentest_tools)
        self.assertIn("Naabu", deep_tools)
        self.assertIn("Feroxbuster", pentest_tools)
        self.assertNotIn("Feroxbuster", deep_tools)


if __name__ == "__main__":
    unittest.main()
