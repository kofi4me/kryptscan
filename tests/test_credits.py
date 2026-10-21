from __future__ import annotations

import sqlite3
import unittest

from app.db import SCHEMA
from app.services.credits import (
    coupon_hash,
    create_quote,
    finalize_scan_credits,
    free_trial_available,
    grant_payment_credits,
    load_valid_quote,
    redeem_coupon,
    refund_scan_credits,
    reserve_scan_credits,
    wallet_snapshot,
)


class CreditLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.execute(
            "INSERT INTO organizations (id, name, email_domain, created_at) VALUES (1, 'Example', 'example.com', '2026-09-30T12:00:00+00:00')"
        )
        self.connection.execute(
            """
            INSERT INTO users (id, organization_id, email, role, is_verified, created_at)
            VALUES (1, 1, 'tester@example.com', 'owner', 1, '2026-09-30T12:00:00+00:00')
            """
        )
        self.connection.execute(
            """
            INSERT INTO targets (
                id, organization_id, target, normalized_target, asset_type,
                ownership_domain, authorization_method, created_by, created_at
            ) VALUES (1, 1, 'example.com', 'example.com', 'website', 'example.com', 'attestation', 1, '2026-09-30T12:00:00+00:00')
            """
        )
        self.user = self.connection.execute("SELECT * FROM users WHERE id = 1").fetchone()

    def tearDown(self) -> None:
        self.connection.close()

    def _insert_scan(self, scan_id: int, tier: str) -> None:
        self.connection.execute(
            """
            INSERT INTO scans (
                id, organization_id, target_id, requested_by, scanner_backend,
                assessment_mode, scan_tier, status, created_at
            ) VALUES (?, 1, 1, 1, ?, 'vulnerability_assessment', ?, 'queued', '2026-09-30T12:00:00+00:00')
            """,
            (scan_id, "free_preview" if tier == "free_preview" else "worker", tier),
        )

    def test_one_free_trial_is_reserved_and_consumed(self) -> None:
        quote_payload = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self.assertTrue(quote_payload["free_trial"])
        quote = load_valid_quote(
            self.connection,
            self.user,
            quote_token=quote_payload["quote_token"],
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self._insert_scan(1, "free_preview")
        reserve_scan_credits(self.connection, self.user, quote, 1)
        finalize_scan_credits(self.connection, self.user, 1)
        self.assertFalse(free_trial_available(self.connection, self.user))
        next_quote = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self.assertEqual(next_quote["service"]["id"], "standard_va")
        self.assertFalse(next_quote["sufficient_credits"])

    def test_paid_credit_reservation_uses_promo_first_and_refunds(self) -> None:
        wallet_snapshot(self.connection, self.user)
        self.connection.execute(
            "UPDATE credit_wallets SET purchased_credits = 2, promotional_credits = 2 WHERE user_id = 1"
        )
        self.connection.execute(
            "INSERT INTO free_trial_claims (user_id, organization_id, status, claimed_at, updated_at) VALUES (1, 1, 'consumed', '2026-09-30', '2026-09-30')"
        )
        payload = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="deep",
        )
        quote = load_valid_quote(
            self.connection,
            self.user,
            quote_token=payload["quote_token"],
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="deep",
        )
        self._insert_scan(2, "full_scan")
        reserve_scan_credits(self.connection, self.user, quote, 2)
        self.assertEqual(wallet_snapshot(self.connection, self.user)["total"], 1)
        refund_scan_credits(self.connection, self.user, 2, "worker unavailable")
        self.assertEqual(wallet_snapshot(self.connection, self.user), {"purchased": 2, "promotional": 2, "total": 4})

    def test_coupon_can_only_be_redeemed_once_per_user(self) -> None:
        self.connection.execute(
            """
            INSERT INTO coupons (
                code_hash, label, credit_amount, max_redemptions, redemption_count,
                active, created_by, created_at
            ) VALUES (?, 'Launch testers', 5, 10, 0, 1, 1, '2026-09-30T12:00:00+00:00')
            """,
            (coupon_hash("TESTER-5"),),
        )
        result = redeem_coupon(self.connection, self.user, "tester-5")
        self.assertEqual(result["credit_balance"]["promotional"], 5)
        with self.assertRaisesRegex(ValueError, "already been redeemed"):
            redeem_coupon(self.connection, self.user, "TESTER-5")

    def test_verified_payment_grants_purchased_credits_once(self) -> None:
        cursor = self.connection.execute(
            """
            INSERT INTO payments (
                organization_id, provider, plan, amount_cents, currency,
                payment_method, status, provider_reference, payer_name,
                payer_email, safe_details_json, created_by, created_at
            ) VALUES (
                1, 'kryptnet_payment_api', 'professional', 2900, 'USD',
                'debit_credit_checkout', 'paid', 'payment-reference-001',
                'Example', 'tester@example.com', '{}', 1, '2026-09-30T12:00:00+00:00'
            )
            """
        )
        payment = self.connection.execute(
            "SELECT * FROM payments WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

        first = grant_payment_credits(self.connection, payment=payment, credits=20)
        second = grant_payment_credits(self.connection, payment=payment, credits=20)

        self.assertEqual(first["credits_granted"], 20)
        self.assertFalse(first["already_granted"])
        self.assertEqual(second["credits_granted"], 0)
        self.assertTrue(second["already_granted"])
        self.assertEqual(wallet_snapshot(self.connection, self.user)["purchased"], 20)
        transaction_count = self.connection.execute(
            "SELECT COUNT(*) FROM credit_transactions WHERE payment_id = ?",
            (payment["id"],),
        ).fetchone()[0]
        self.assertEqual(transaction_count, 1)

    def test_quote_is_bound_to_target_mode_and_service(self) -> None:
        payload = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        mismatch = load_valid_quote(
            self.connection,
            self.user,
            quote_token=payload["quote_token"],
            target="different.example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self.assertIsNone(mismatch)

    def test_quote_cannot_be_reserved_twice(self) -> None:
        payload = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        quote = load_valid_quote(
            self.connection,
            self.user,
            quote_token=payload["quote_token"],
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self._insert_scan(3, "free_preview")
        reserve_scan_credits(self.connection, self.user, quote, 3)
        self._insert_scan(4, "free_preview")
        with self.assertRaisesRegex(ValueError, "already used"):
            reserve_scan_credits(self.connection, self.user, quote, 4)

    def test_free_trial_is_shared_by_the_organization(self) -> None:
        self.connection.execute(
            """
            INSERT INTO users (id, organization_id, email, role, is_verified, created_at)
            VALUES (2, 1, 'analyst@example.com', 'analyst', 1, '2026-09-30T12:00:00+00:00')
            """
        )
        analyst = self.connection.execute("SELECT * FROM users WHERE id = 2").fetchone()
        quote_payload = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        quote = load_valid_quote(
            self.connection,
            self.user,
            quote_token=quote_payload["quote_token"],
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self._insert_scan(5, "free_preview")
        reserve_scan_credits(self.connection, self.user, quote, 5)
        finalize_scan_credits(self.connection, self.user, 5)

        analyst_quote = create_quote(
            self.connection,
            analyst,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self.assertEqual(analyst_quote["service"]["id"], "standard_va")

    def test_refunded_free_trial_can_be_retried(self) -> None:
        quote_payload = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        quote = load_valid_quote(
            self.connection,
            self.user,
            quote_token=quote_payload["quote_token"],
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self._insert_scan(6, "free_preview")
        reserve_scan_credits(self.connection, self.user, quote, 6)
        refund_scan_credits(self.connection, self.user, 6, "worker unavailable")

        retry = create_quote(
            self.connection,
            self.user,
            target="example.com",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
        )
        self.assertEqual(retry["service"]["id"], "free_basic_va")

    def test_network_fingerprint_caps_cross_organization_free_trials(self) -> None:
        fingerprint = "network-hmac"
        for organization_id in (2, 3, 4):
            self.connection.execute(
                "INSERT INTO organizations (id, name, email_domain, created_at) VALUES (?, ?, ?, '2026-09-30')",
                (organization_id, f"Org {organization_id}", f"org{organization_id}.example"),
            )
            self.connection.execute(
                """
                INSERT INTO users (id, organization_id, email, role, is_verified, created_at)
                VALUES (?, ?, ?, 'owner', 1, '2026-09-30')
                """,
                (organization_id, organization_id, f"owner@org{organization_id}.example"),
            )
        for organization_id in (2, 3):
            self.connection.execute(
                """
                INSERT INTO free_trial_claims (
                    user_id, organization_id, status, request_fingerprint, claimed_at, updated_at
                ) VALUES (?, ?, 'consumed', ?, '2026-09-30', '2026-09-30')
                """,
                (organization_id, organization_id, fingerprint),
            )
        third_user = self.connection.execute("SELECT * FROM users WHERE id = 4").fetchone()
        quote = create_quote(
            self.connection,
            third_user,
            target="org4.example",
            assessment_mode="vulnerability_assessment",
            service_level="standard",
            request_fingerprint=fingerprint,
        )
        self.assertEqual(quote["service"]["id"], "standard_va")


if __name__ == "__main__":
    unittest.main()
