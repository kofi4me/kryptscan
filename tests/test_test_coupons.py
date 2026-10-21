from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.db import SCHEMA
from app.services.credits import coupon_hash, redeem_coupon
from ops.create_test_coupons import TEST_PACKS, find_coupon_admin, provision_test_coupons


class TestCouponProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.execute(
            "INSERT INTO organizations (id, name, email_domain, created_at) VALUES (1, 'KryptNet', 'kryptnet.org', '2026-10-21T12:00:00+00:00')"
        )
        self.connection.execute(
            """
            INSERT INTO users (id, organization_id, email, role, is_verified, created_at)
            VALUES (1, 1, 'admin@kryptnet.org', 'super_admin', 1, '2026-10-21T12:00:00+00:00')
            """
        )
        self.connection.execute(
            """
            INSERT INTO users (id, organization_id, email, role, is_verified, created_at)
            VALUES (2, 1, 'tester@kryptnet.org', 'owner', 1, '2026-10-21T12:00:00+00:00')
            """
        )

    def tearDown(self) -> None:
        self.connection.close()

    def test_provisions_hashed_coupons_for_each_credit_pack(self) -> None:
        fixed_now = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        with patch("ops.create_test_coupons._utcnow", return_value=fixed_now):
            coupons = provision_test_coupons(
                self.connection,
                created_by=1,
                expires_at=fixed_now + timedelta(days=7),
            )

        self.assertEqual([coupon["credits"] for coupon in coupons], [20, 45, 90])
        self.assertEqual([coupon["price_usd"] for coupon in coupons], [29, 59, 99])
        self.assertEqual(len({coupon["code"] for coupon in coupons}), len(TEST_PACKS))

        rows = self.connection.execute(
            "SELECT code_hash, credit_amount, max_redemptions, active FROM coupons ORDER BY id"
        ).fetchall()
        self.assertEqual([row["credit_amount"] for row in rows], [20, 45, 90])
        self.assertTrue(all(row["max_redemptions"] == 1 for row in rows))
        self.assertTrue(all(row["active"] == 1 for row in rows))
        audit_count = self.connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'admin.test_coupon_created'"
        ).fetchone()[0]
        self.assertEqual(audit_count, 3)
        for coupon, row in zip(coupons, rows, strict=True):
            self.assertEqual(row["code_hash"], coupon_hash(str(coupon["code"])))
            self.assertNotEqual(row["code_hash"], coupon["code"])

        tester = self.connection.execute("SELECT * FROM users WHERE id = 2").fetchone()
        result = redeem_coupon(self.connection, tester, str(coupons[0]["code"]))
        self.assertEqual(result["credits_granted"], 20)

    def test_uses_verified_admin_as_coupon_creator(self) -> None:
        admin = find_coupon_admin(self.connection)
        self.assertEqual(admin["email"], "admin@kryptnet.org")
        with self.assertRaisesRegex(ValueError, "No verified KryptScan administrator"):
            find_coupon_admin(self.connection, "missing@kryptnet.org")


if __name__ == "__main__":
    unittest.main()
