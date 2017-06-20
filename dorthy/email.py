import logging
import os
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from dorthy.settings import config

logger = logging.getLogger(__name__)

default_from = config.mail.from_address
default_reply_to = config.mail.get("reply_to_address")
log_message = config.mail.enabled("log_message")

_template_paths = []
for path in config.mail.templates:
    if path.startswith('/'):
        _template_paths.append(path)
    else:
        _template_paths.append((os.path.join(os.getcwd(), path)))

template_env = Environment(loader=FileSystemLoader(_template_paths))


def _get_template(template_name, extension):
    try:
        return template_env.get_template(template_name + "." + extension)
    except TemplateNotFound:
        return None


def send_message(to_address, from_address=default_from, subject=None,
                 reply_to=None, use_reply_to=True, text_msg=None, html_msg=None):

    assert text_msg or html_msg, "A message must be sent - html or text or both."

    msg = MIMEMultipart("alternative")
    if subject:
        msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = to_address

    if text_msg:
        msg.attach(MIMEText(text_msg, "plain"))

    if html_msg:
        msg.attach(MIMEText(html_msg, "html"))

    if log_message:
        logger.info(msg.as_string())
    else:
        s = None
        try:
            use_ssl = "use_ssl" in config.mail and config.mail.enabled("use_ssl")
            if use_ssl:
                s = smtplib.SMTP_SSL(host=config.mail.host, port=config.mail.get("port", 465))
            else:
                s = smtplib.SMTP(host=config.mail.host, port=config.mail.get("port", 25))

            if config.mail.enabled("debug"):
                s.set_debuglevel(1)
            if not use_ssl and config.mail.enabled("use_starttls"):
                s.starttls()

            s.login(config.mail.username, config.mail.password)

            if use_reply_to:
                if not reply_to:
                    reply_to = default_reply_to if default_reply_to else from_address
                msg.add_header("Reply-to", reply_to)

            s.sendmail(from_address, to_address, msg.as_string())

        finally:
            if s:
                s.quit()


def send_template(template_name, to_address, from_address=default_from, subject=None,
                  reply_to=None, use_reply_to=True, **kwargs):

    text_template = _get_template(template_name, "txt")
    html_template = _get_template(template_name, "html")

    text_msg = None
    if text_template:
        text_msg = text_template.render(**kwargs)

    html_msg = None
    if html_template:
        html_msg = html_template.render(**kwargs)

    send_message(to_address, from_address=from_address, subject=subject,
                 reply_to=reply_to, use_reply_to=use_reply_to, text_msg=text_msg, html_msg=html_msg)
