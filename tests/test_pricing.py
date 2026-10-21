from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.main import (
    PLAN_CATALOG,
    PUBLIC_PRICING_PLANS,
    _authorize_net_callback_urls,
    _public_page,
    authorize_net_payment_cancel,
    authorize_net_payment_complete,
    create_payment_intent,
)
from app.models import PaymentIntentRequest


class PricingCatalogTests(unittest.TestCase):
    @staticmethod
    def _request() -> Request:
        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/pricing",
                "raw_path": b"/pricing",
                "query_string": b"",
                "headers": [(b"host", b"kryptscan.kryptnet.org")],
                "client": ("127.0.0.1", 12345),
                "server": ("kryptscan.kryptnet.org", 443),
            }
        )

    def test_credit_pack_prices_and_credits_match_launch_catalog(self) -> None:
        expected = {
            "professional": (2900, 20),
            "business": (5900, 45),
            "msp": (9900, 90),
        }

        self.assertEqual(
            {
                plan_id: (plan["amount_cents"], plan["credits"])
                for plan_id, plan in PLAN_CATALOG.items()
            },
            expected,
        )
        self.assertEqual(
            {
                plan["id"]: (plan["price_usd"], plan["credits"])
                for plan in PUBLIC_PRICING_PLANS
            },
            {
                plan_id: (amount_cents // 100, credits)
                for plan_id, (amount_cents, credits) in expected.items()
            },
        )

    def test_authenticated_pricing_page_offers_checkout_and_sign_out(self) -> None:
        with patch("app.main.get_current_user", return_value={"id": 1}):
            response = _public_page(self._request(), "pricing")
        body = response.body.decode("utf-8")

        self.assertIn("Sign Out", body)
        self.assertIn("Select Plan", body)
        self.assertIn("$29", body)
        self.assertIn("20 purchased scan credits", body)
        self.assertIn("$59", body)
        self.assertIn("45 purchased scan credits", body)
        self.assertIn("$99", body)
        self.assertIn("90 purchased scan credits", body)
        self.assertNotIn("Sign In", body)
        self.assertNotIn("Create Account", body)
        self.assertEqual(response.headers["cache-control"], "private, no-store, max-age=0")
        self.assertEqual(response.headers["vary"], "Cookie")

    def test_visitor_pricing_page_offers_account_actions(self) -> None:
        with patch(
            "app.main.get_current_user",
            side_effect=HTTPException(status_code=401),
        ):
            response = _public_page(self._request(), "pricing")
        body = response.body.decode("utf-8")

        self.assertIn("Sign In", body)
        self.assertIn("Create Account", body)
        self.assertNotIn("Sign Out", body)
        self.assertNotIn("Select Plan", body)

    def test_completed_accounts_can_purchase_regardless_of_role(self) -> None:
        payment_settings = SimpleNamespace(
            payment_required=True,
            payment_provider="authorize_net",
            rate_limit_enabled=False,
            kryptnet_payment_api_url="",
        )
        for role in ("owner", "analyst", "client_viewer", "admin", "super_admin"):
            user = {
                "role": role,
                "profile_completed_at": "2026-10-20T00:00:00+00:00",
                "safe_use_accepted": 1,
                "data_protection_accepted": 1,
                "password_hash": "configured",
            }
            with self.subTest(role=role), patch("app.main.settings", payment_settings):
                result = create_payment_intent(
                    self._request(),
                    PaymentIntentRequest(plan="professional"),
                    user,
                )

                self.assertEqual(result["provider"], "authorize_net")
                self.assertEqual(result["plan"]["credits"], 20)

    def test_authorize_net_callbacks_use_clean_paths(self) -> None:
        complete = authorize_net_payment_complete()
        cancel = authorize_net_payment_cancel()

        self.assertEqual(complete.status_code, 303)
        self.assertEqual(complete.headers["location"], "/?payment=complete")
        self.assertEqual(cancel.status_code, 303)
        self.assertEqual(cancel.headers["location"], "/?payment=cancelled")

        callback_settings = SimpleNamespace(public_base_url="https://kryptscan.kryptnet.org")
        with patch("app.main.settings", callback_settings):
            return_url, cancel_url = _authorize_net_callback_urls(self._request())

        self.assertEqual(return_url, "https://kryptscan.kryptnet.org/payments/authorize-net/complete")
        self.assertEqual(cancel_url, "https://kryptscan.kryptnet.org/payments/authorize-net/cancel")
        self.assertNotIn("?", return_url)
        self.assertNotIn("?", cancel_url)


if __name__ == "__main__":
    unittest.main()
