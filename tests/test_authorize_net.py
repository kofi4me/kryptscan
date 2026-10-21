from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

from app.services.authorize_net import (
    AuthorizeNetError,
    authorize_net_endpoints,
    create_hosted_payment_token,
    validate_paid_transaction,
    verify_webhook_signature,
)


class AuthorizeNetTests(unittest.TestCase):
    def test_environment_selects_sandbox_and_production_hosts(self) -> None:
        self.assertIn("apitest.authorize.net", authorize_net_endpoints("sandbox")[0])
        self.assertEqual(
            authorize_net_endpoints("production")[1],
            "https://accept.authorize.net/payment/payment",
        )
        with self.assertRaisesRegex(AuthorizeNetError, "sandbox or production"):
            authorize_net_endpoints("invalid")

    @patch("app.services.authorize_net._post_json")
    def test_hosted_checkout_uses_server_amount_and_reference(self, post_json) -> None:
        post_json.return_value = {
            "getHostedPaymentPageResponse": {
                "token": "hosted-token",
                "messages": {"resultCode": "Ok", "message": [{"code": "I00001", "text": "Successful."}]},
            }
        }
        result = create_hosted_payment_token(
            api_login_id="login",
            transaction_key="transaction-key",
            environment="sandbox",
            reference="ks123456789012345678",
            amount_cents=2900,
            currency="USD",
            email="tester@example.com",
            description="KryptScan Professional credit pack",
            return_url="https://example.com/?payment=complete",
            cancel_url="https://example.com/?payment=cancelled",
        )
        self.assertEqual(result["token"], "hosted-token")
        request_payload = post_json.call_args.args[1]["getHostedPaymentPageRequest"]
        self.assertEqual(request_payload["refId"], "ks123456789012345678")
        self.assertEqual(request_payload["transactionRequest"]["amount"], "29.00")
        self.assertEqual(request_payload["transactionRequest"]["currencyCode"], "USD")
        self.assertEqual(request_payload["transactionRequest"]["order"]["invoiceNumber"], "ks123456789012345678")

    def test_webhook_signature_uses_authorize_net_hmac_sha512_format(self) -> None:
        raw_body = json.dumps({"eventType": "net.authorize.payment.authcapture.created"}).encode("utf-8")
        signature_key = "ab" * 64
        signature = hmac.new(bytes.fromhex(signature_key), raw_body, hashlib.sha512).hexdigest()
        self.assertTrue(verify_webhook_signature(raw_body, f"sha512={signature}", signature_key))
        self.assertFalse(verify_webhook_signature(raw_body + b" ", f"sha512={signature}", signature_key))
        self.assertFalse(verify_webhook_signature(raw_body, f"sha512={signature}", "not-hex"))

    def test_transaction_validation_checks_reference_amount_currency_and_status(self) -> None:
        response = {
            "refId": "ks123456789012345678",
            "transaction": {
                "transId": "60123456789",
                "transactionType": "authCaptureTransaction",
                "transactionStatus": "capturedPendingSettlement",
                "authAmount": "29.00",
                "currencyCode": "USD",
                "order": {"invoiceNumber": "ks123456789012345678"},
            },
        }
        verified = validate_paid_transaction(
            response,
            expected_reference="ks123456789012345678",
            expected_amount_cents=2900,
            expected_currency="USD",
        )
        self.assertEqual(verified["transaction_id"], "60123456789")
        with self.assertRaisesRegex(AuthorizeNetError, "amount"):
            validate_paid_transaction(
                response,
                expected_reference="ks123456789012345678",
                expected_amount_cents=5900,
                expected_currency="USD",
            )
        with self.assertRaisesRegex(AuthorizeNetError, "reference"):
            validate_paid_transaction(
                response,
                expected_reference="ks000000000000000000",
                expected_amount_cents=2900,
                expected_currency="USD",
            )


if __name__ == "__main__":
    unittest.main()
