import smtplib
from email.message import EmailMessage


def send_email_report(
    recipient_email,
    subject,
    body,
    attachment_path
):

    from app import (
        MAIL_USERNAME,
        MAIL_PASSWORD,
        MAIL_SERVER,
        MAIL_PORT
    )

    message = EmailMessage()

    message["From"] = MAIL_USERNAME
    message["To"] = recipient_email
    message["Subject"] = subject

    message.set_content(body)

    with open(attachment_path, "rb") as file:
        file_data = file.read()

    message.add_attachment(
        file_data,
        maintype="application",
        subtype="pdf",
        filename=attachment_path
    )

    with smtplib.SMTP(
        MAIL_SERVER,
        MAIL_PORT
    ) as server:

        server.starttls()

        server.login(
            MAIL_USERNAME,
            MAIL_PASSWORD
        )

        server.send_message(message)