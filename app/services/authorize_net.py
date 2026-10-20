from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from typing import Any


class AuthorizeNetError(RuntimeError):
    pass


def authorize_net_endpoints(environment: str) -> tuple[str, str]:
    normalized = (environment or "sandbox").strip().lower()
    if normalized == "production":
        return (
            "https://api.authorize.net/xml/v1/request.api",
            "https://accept.authorize.net/payment/payment",
        )
    if normalized == "sandbox":
        return (
            "https://apitest.authorize.net/xml/v1/request.api",
            "https://test.authorize.net/payment/payment",
        )
    raise AuthorizeNetError("AUTHORIZE_NET_ENVIRONMENT must be sandbox or production.")


def _post_json(url: str, payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw_response = response.read().decode("utf-8-sig")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise AuthorizeNetError("Authorize.Net could not be reached.") from exc
    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        raise AuthorizeNetError("Authorize.Net returned an invalid response.") from exc
    if not isinstance(parsed, dict):
        raise AuthorizeNetError("Authorize.Net returned an unexpected response.")
    return parsed


def _response_error(response: dict[str, Any], response_name: str) -> AuthorizeNetError | None:
    payload = response.get(response_name)
    if not isinstance(payload, dict):
        return AuthorizeNetError("Authorize.Net returned an unexpected response.")
    messages = payload.get("messages") or {}
    if str(messages.get("resultCode") or "").lower() == "ok":
        return None
    message_items = messages.get("message") or []
    if isinstance(message_items, dict):
        message_items = [message_items]
    detail = "; ".join(
        str(item.get("text") or item.get("code") or "").strip()
        for item in message_items
        if isinstance(item, dict)
    )
    return AuthorizeNetError(detail or "Authorize.Net rejected the request.")


def create_hosted_payment_token(
    *,
    api_login_id: str,
    transaction_key: str,
    environment: str,
    reference: str,
    amount_cents: int,
    currency: str,
    email: str,
    description: str,
    return_url: str,
    cancel_url: str,
    timeout_seconds: int = 20,
) -> dict[str, str]:
    if not api_login_id or not transaction_key:
        raise AuthorizeNetError("Authorize.Net merchant credentials are not configured.")
    if amount_cents <= 0:
        raise AuthorizeNetError("The checkout amount must be greater than zero.")
    if len(reference) > 20:
        raise AuthorizeNetError("The Authorize.Net payment reference cannot exceed 20 characters.")
    api_url, hosted_form_url = authorize_net_endpoints(environment)
    amount = f"{Decimal(amount_cents) / Decimal(100):.2f}"
    payload = {
        "getHostedPaymentPageRequest": {
            "merchantAuthentication": {
                "name": api_login_id,
                "transactionKey": transaction_key,
            },
            "refId": reference,
            "transactionRequest": {
                "transactionType": "authCaptureTransaction",
                "amount": amount,
                "currencyCode": currency.upper(),
                "order": {
                    "invoiceNumber": reference,
                    "description": description[:255],
                },
                "customer": {"email": email},
            },
            "hostedPaymentSettings": {
                "setting": [
                    {
                        "settingName": "hostedPaymentReturnOptions",
                        "settingValue": json.dumps(
                            {
                                "showReceipt": True,
                                "url": return_url,
                                "urlText": "Return to KryptScan",
                                "cancelUrl": cancel_url,
                                "cancelUrlText": "Cancel",
                            },
                            separators=(",", ":"),
                        ),
                    },
                    {
                        "settingName": "hostedPaymentButtonOptions",
                        "settingValue": json.dumps({"text": "Pay securely"}, separators=(",", ":")),
                    },
                    {
                        "settingName": "hostedPaymentPaymentOptions",
                        "settingValue": json.dumps(
                            {"cardCodeRequired": True, "showCreditCard": True, "showBankAccount": False},
                            separators=(",", ":"),
                        ),
                    },
                    {
                        "settingName": "hostedPaymentShippingAddressOptions",
                        "settingValue": json.dumps({"show": False, "required": False}, separators=(",", ":")),
                    },
                    {
                        "settingName": "hostedPaymentCustomerOptions",
                        "settingValue": json.dumps(
                            {"showEmail": False, "requiredEmail": True, "addPaymentProfile": False},
                            separators=(",", ":"),
                        ),
                    },
                    {
                        "settingName": "hostedPaymentOrderOptions",
                        "settingValue": json.dumps(
                            {"show": True, "merchantName": "KryptNet LLC"},
                            separators=(",", ":"),
                        ),
                    },
                ]
            },
        }
    }
    response = _post_json(api_url, payload, timeout_seconds)
    error = _response_error(response, "getHostedPaymentPageResponse")
    if error:
        raise error
    token = str(response["getHostedPaymentPageResponse"].get("token") or "").strip()
    if not token:
        raise AuthorizeNetError("Authorize.Net did not return a hosted payment token.")
    return {"token": token, "hosted_form_url": hosted_form_url}


def get_transaction_details(
    *,
    api_login_id: str,
    transaction_key: str,
    environment: str,
    transaction_id: str,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    if not api_login_id or not transaction_key:
        raise AuthorizeNetError("Authorize.Net merchant credentials are not configured.")
    if not transaction_id or not transaction_id.isdigit():
        raise AuthorizeNetError("Authorize.Net supplied an invalid transaction ID.")
    api_url, _ = authorize_net_endpoints(environment)
    response = _post_json(
        api_url,
        {
            "getTransactionDetailsRequest": {
                "merchantAuthentication": {
                    "name": api_login_id,
                    "transactionKey": transaction_key,
                },
                "transId": transaction_id,
            }
        },
        timeout_seconds,
    )
    error = _response_error(response, "getTransactionDetailsResponse")
    if error:
        raise error
    return response["getTransactionDetailsResponse"]


def verify_webhook_signature(raw_body: bytes, signature_header: str, signature_key: str) -> bool:
    if not raw_body or not signature_header or not signature_key:
        return False
    supplied = signature_header.strip()
    if supplied.lower().startswith("sha512="):
        supplied = supplied.split("=", 1)[1]
    try:
        key = bytes.fromhex(signature_key.strip())
    except ValueError:
        return False
    expected = hmac.new(key, raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected.lower(), supplied.lower())


def validate_paid_transaction(
    response: dict[str, Any],
    *,
    expected_reference: str,
    expected_amount_cents: int,
    expected_currency: str,
) -> dict[str, str]:
    transaction = response.get("transaction")
    if not isinstance(transaction, dict):
        raise AuthorizeNetError("Authorize.Net transaction details were incomplete.")
    transaction_status = str(transaction.get("transactionStatus") or "").strip()
    accepted_statuses = {"capturedPendingSettlement", "settledSuccessfully"}
    if transaction_status not in accepted_statuses:
        raise AuthorizeNetError(f"Authorize.Net transaction is not payable: {transaction_status or 'unknown status'}.")
    if str(transaction.get("transactionType") or "") != "authCaptureTransaction":
        raise AuthorizeNetError("Authorize.Net transaction type did not match the checkout request.")
    order = transaction.get("order") or {}
    actual_reference = str(response.get("refId") or order.get("invoiceNumber") or "").strip()
    if not hmac.compare_digest(actual_reference, expected_reference):
        raise AuthorizeNetError("Authorize.Net transaction reference did not match the checkout.")
    raw_amount = transaction.get("authAmount")
    if raw_amount in {None, ""}:
        raw_amount = transaction.get("settleAmount")
    try:
        amount_cents = int((Decimal(str(raw_amount)) * Decimal(100)).quantize(Decimal("1")))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise AuthorizeNetError("Authorize.Net transaction amount was invalid.") from exc
    if amount_cents != expected_amount_cents:
        raise AuthorizeNetError("Authorize.Net transaction amount did not match the checkout.")
    currency = str(transaction.get("currencyCode") or "").upper()
    if currency != expected_currency.upper():
        raise AuthorizeNetError("Authorize.Net transaction currency did not match the checkout.")
    return {
        "transaction_id": str(transaction.get("transId") or ""),
        "transaction_status": transaction_status,
        "amount_cents": str(amount_cents),
        "currency": currency,
    }
