# KryptScan Credit Pricing

## Launch Rules

- Each verified account receives one Free Basic Vulnerability Assessment.
- The free assessment produces a simple web-only summary. PDF, JSON, email delivery, AI analysis, deep scanning, and penetration testing are not included.
- Existing accounts with prior scan activity do not receive another free assessment.
- Paid scans require a server-issued quote and explicit user acceptance before launch.
- Quotes expire after 15 minutes and are bound to the user, organization, target, assessment mode, and service level.

## Credit Costs

| Service | Credits | Report access |
| --- | ---: | --- |
| Free Basic Vulnerability Assessment | 0, once | Web summary only |
| Standard Vulnerability Assessment | 1 | Web, PDF, JSON |
| Deep Vulnerability Assessment | 3 | Web, PDF, JSON |
| Ethical Penetration Test | 8 | Web, PDF, JSON |
| Remediation Retest | 1 | Web, PDF, JSON |

Deep VA adds expanded safe network and web surface mapping. Ethical Pen-Testing adds the approved rules-of-engagement workflow and deeper content/API validation.

## Planned Monthly Packages

| Plan | Monthly price | Included credits |
| --- | ---: | ---: |
| Professional | $79 | 10 |
| Business | $199 | 30 |
| MSP | $499 | 100 |

Checkout remains disabled during launch testing. Activating commercial payments requires mapping successful payment webhooks to purchased-credit ledger entries.

## Credit Lifecycle

1. The workspace requests a signed server-side quote.
2. The user reviews the cost and remaining balance.
3. The user confirms authorization and accepts the charge.
4. Promotional credits are reserved first, followed by purchased credits.
5. Credits are finalized when the scan completes.
6. Reserved credits are automatically returned for scanner scheduling failures, worker communication failures, and platform timeouts.
7. Target unavailability after tools have consumed resources does not automatically qualify for a refund.

## Coupons

Admins create coupons in the hidden `/kryptnet-admin` console. Coupon codes are stored as SHA-256 hashes and cannot be recovered from the database. Each coupon defines a credit grant, expiry, and total redemption limit. Each user may redeem a coupon once.

Promotional credits are tracked separately from purchased credits and are consumed first.

## Public Pages

- `/pricing`
- `/about`
- `/policies`
- `/policies/terms`
- `/policies/privacy`
- `/policies/acceptable-use`
- `/policies/credits-refunds`
- `/policies/vulnerability-disclosure`
- `/support`

The policy wording is launch guidance and should receive legal review before commercial checkout is activated.
