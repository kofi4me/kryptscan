from __future__ import annotations

import smtplib
from email.message import EmailMessage

from app.config import Settings


class BaseEmailSender:
    def send_verification_code(self, email: str, code: str, domain: str) -> None:
        raise NotImplementedError

    def send_password_reset_code(self, email: str, code: str) -> None:
        raise NotImplementedError

    def send_assessment_report(
        self,
        email: str,
        target: str,
        pdf_filename: str,
        pdf_bytes: bytes,
        summary: str,
    ) -> None:
        raise NotImplementedError


class ConsoleEmailSender(BaseEmailSender):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def send_verification_code(self, email: str, code: str, domain: str) -> None:
        print(
            f"[{self.settings.app_name}] Verification code for {email} "
            f"(authorized domain {domain}): {code}"
        )

    def send_password_reset_code(self, email: str, code: str) -> None:
        print(f"[{self.settings.app_name}] Password reset code for {email}: {code}")

    def send_assessment_report(
        self,
        email: str,
        target: str,
        pdf_filename: str,
        pdf_bytes: bytes,
        summary: str,
    ) -> None:
        print(
            f"[{self.settings.app_name}] Assessment report for {target} prepared for {email}: "
            f"{pdf_filename} ({len(pdf_bytes)} bytes)"
        )
        print(summary)


class SmtpEmailSender(BaseEmailSender):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def send_verification_code(self, email: str, code: str, domain: str) -> None:
        message = EmailMessage()
        message["Subject"] = f"{self.settings.app_name} verification code"
        message["From"] = self.settings.email_from
        message["To"] = email
        message.set_content(
            "Use this code to authorize your vulnerability assessment account.\n\n"
            f"Verification code: {code}\n"
            f"Authorized domain: {domain}\n\n"
            "This code expires in 10 minutes.\n\n"
            "If you did not request this code, ignore this message."
        )

        smtp_factory = smtplib.SMTP_SSL if self.settings.smtp_use_ssl else smtplib.SMTP
        with smtp_factory(self.settings.smtp_host, self.settings.smtp_port, timeout=30) as smtp:
            if self.settings.smtp_use_tls and not self.settings.smtp_use_ssl:
                smtp.starttls()
            if self.settings.smtp_username:
                smtp.login(self.settings.smtp_username, self.settings.smtp_password)
            smtp.send_message(message)

    def send_password_reset_code(self, email: str, code: str) -> None:
        message = EmailMessage()
        message["Subject"] = f"{self.settings.app_name} password reset code"
        message["From"] = self.settings.email_from
        message["To"] = email
        message.set_content(
            "Use this code to reset your KryptNet password.\n\n"
            f"Password reset code: {code}\n\n"
            "This code expires in 10 minutes. If you did not request it, ignore this message."
        )

        smtp_factory = smtplib.SMTP_SSL if self.settings.smtp_use_ssl else smtplib.SMTP
        with smtp_factory(self.settings.smtp_host, self.settings.smtp_port, timeout=30) as smtp:
            if self.settings.smtp_use_tls and not self.settings.smtp_use_ssl:
                smtp.starttls()
            if self.settings.smtp_username:
                smtp.login(self.settings.smtp_username, self.settings.smtp_password)
            smtp.send_message(message)

    def send_assessment_report(
        self,
        email: str,
        target: str,
        pdf_filename: str,
        pdf_bytes: bytes,
        summary: str,
    ) -> None:
        message = EmailMessage()
        message["Subject"] = f"{self.settings.app_name} assessment report for {target}"
        message["From"] = self.settings.email_from
        message["To"] = email
        message.set_content(
            "Your vulnerability assessment has completed.\n\n"
            f"Target: {target}\n\n"
            f"{summary}\n\n"
            "The PDF assessment report is attached."
        )
        message.add_attachment(
            pdf_bytes,
            maintype="application",
            subtype="pdf",
            filename=pdf_filename,
        )

        smtp_factory = smtplib.SMTP_SSL if self.settings.smtp_use_ssl else smtplib.SMTP
        with smtp_factory(self.settings.smtp_host, self.settings.smtp_port, timeout=30) as smtp:
            if self.settings.smtp_use_tls and not self.settings.smtp_use_ssl:
                smtp.starttls()
            if self.settings.smtp_username:
                smtp.login(self.settings.smtp_username, self.settings.smtp_password)
            smtp.send_message(message)


def get_email_sender(settings: Settings) -> BaseEmailSender:
    if settings.email_delivery == "smtp":
        return SmtpEmailSender(settings)
    return ConsoleEmailSender(settings)
