# Deploy Kryptnet with GitHub and Render

This is the quickest path to put Kryptnet online at:

```text
https://pentest.kryptnet.org
```

Render will host the web app. GitHub will store the code and trigger redeploys when we push improvements.

## 1. Create a Private GitHub Repository

Recommended repository name:

```text
kryptnet-pentest
```

Keep it private because this app includes commercial backend logic.

From this folder:

```powershell
git add .
git commit -m "Prepare Kryptnet Render deployment"
git branch -M main
git remote add origin https://github.com/<your-github-user-or-org>/kryptnet-pentest.git
git push -u origin main
```

Do not commit `.env`, `.env.scanner`, `.env.production`, local database files, report PDFs, or logs.

## 2. Create Render Blueprint

1. Sign in to Render.
2. Choose **New**.
3. Choose **Blueprint**.
4. Connect the private GitHub repository.
5. Select the repository containing `render.yaml`.
6. Apply the blueprint.

Render will create the `kryptnet-pentest` web service.

## 3. Add Required Render Environment Secrets

In Render, open the `kryptnet-pentest` service, then add these environment variables if they are not already set by the blueprint:

```env
KRYPTNET_PAYMENT_WEBHOOK_SECRET=<real-webhook-secret>
OPENAI_API_KEY=<real-openai-api-key>
```

The Render blueprint starts with:

```env
APP_ENV=staging
```

This lets us test the public web app before the payment webhook is live. After SMTP and the KryptNet payment webhook are configured, change it to:

```env
APP_ENV=production
```

For live email delivery, change:

```env
EMAIL_DELIVERY=smtp
SMTP_HOST=<smtp-host>
SMTP_USERNAME=<smtp-user>
SMTP_PASSWORD=<smtp-password>
EMAIL_FROM=security@kryptnet.org
```

The first test deployment can use:

```env
EMAIL_DELIVERY=console
```

In console mode, OTP codes appear in Render service logs.

## 4. Add Custom Domain in Render

In Render:

1. Open the `kryptnet-pentest` web service.
2. Go to **Settings**.
3. Open **Custom Domains**.
4. Add:

```text
pentest.kryptnet.org
```

Render will show the DNS record to create.

## 5. Configure DNS

In the DNS manager for `kryptnet.org`, create the DNS record Render gives you.

It is usually a CNAME similar to:

```text
pentest  CNAME  kryptnet-pentest.onrender.com
```

Use the exact value shown by Render.

## 6. First Live Test

Open:

```text
https://pentest.kryptnet.org
```

Then test:

1. Homepage loads.
2. Email verification sends or logs OTP.
3. Registration page opens after OTP verification.
4. Vulnerability Assessment shows Free Scan and Full Scan.
5. Free Scan runs and shows web-only summary.
6. Full Scan requires payment.
7. Ethical Pen-Testing has no free option.
8. Report download requires authentication.

## 7. Important Render Note

The Render web service is best for the public app, dashboard, user flow, payment flow, free scan preview, AI report drafting, and PDF generation.

The full pentesting scanner worker uses heavier security tools such as Nmap, ZAP, Nikto, Trivy, and Amass. If Render does not allow those tools or network scanning behavior, deploy the scanner worker separately on an Ubuntu VPS and connect it to Kryptnet later.
