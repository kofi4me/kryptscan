from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from app.main import dashboard
from app.models import DashboardResponse


class WorkspaceUiTests(unittest.TestCase):
    @staticmethod
    def _source(path: str) -> str:
        return (Path(__file__).parents[1] / path).read_text(encoding="utf-8")

    def test_workspace_keeps_purchase_controls_without_internal_status_panels(self) -> None:
        template = self._source("app/templates/index.html")
        script = self._source("app/static/app.js")

        self.assertIn("Purchase Scan Credits", template)
        self.assertNotIn('id="payment-list"', template)
        self.assertNotIn('id="commercial-readiness"', template)
        self.assertNotIn('id="scanner-health-grid"', template)
        self.assertNotIn("Scanner Ready", script)
        self.assertNotIn("managed scanner worker", script)
        self.assertNotIn("renderPayments", script)

    def test_dashboard_does_not_return_payment_attempt_history(self) -> None:
        fields = getattr(DashboardResponse, "model_fields", None) or DashboardResponse.__fields__

        self.assertNotIn("payments", fields)
        self.assertNotIn("FROM payments", inspect.getsource(dashboard))


if __name__ == "__main__":
    unittest.main()
