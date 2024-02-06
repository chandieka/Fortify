import smtplib

from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from abc import ABC, abstractmethod
from fortify.utils.logger import logger

EXPORT_FORMATS = [
    ".json",
    ".yaml",
    ".yml",
    ".pdf"
]

class Exporter(ABC):
    def __init__(self):
        """Initialize the Exporter"""
        self.driver = 'filesystem'
        
    @abstractmethod
    def export(self, serializer):
        """Export the benchmark results"""
        self.s = serializer

    def save(self, export_data):
        """Save the benchmark results to filesystem"""
        if self.driver == "filesystem":
            self.s.save_to_path(export_data, self.full_path)
            logger.display(
                f"OK: Export successfull - {self.full_path}", color="light_yellow"
            )

    def mail(self, serialized_data):
        """Email the Serialized data as an attachement by mail"""
        logger.v(f"OK: Preparing data to be email")
        msg = MIMEMultipart()
        msg['Subject'] = self.message_subject
        msg['From'] = self.message_from
        msg["To"] = self.message_to

        part = MIMEBase('application', "octet-stream")
        part.set_payload(serialized_data)

        logger.vv(f"OK: Encoding data to base64")
        encoders.encode_base64(part)

        part.add_header(
            'Content-Disposition',
            'attachment; filename={}'.format(self.message_file_name)
        )
        msg.attach(MIMEText(self.message_body, 'plain'))
        msg.attach(part)

        try:
            logger.display(f"OK: Sending export data to {self.message_to}", color="light_yellow")
            connection = smtplib.SMTP(
                host=self.smtp_host, 
                port=self.smtp_port,
                timeout=10
            )
            connection.starttls()
            connection.send_message(msg)
            connection.quit()
            logger.display("OK: Email successfully sent", color="light_yellow")
        except Exception as e:
            raise e

    def set_full_path(self, path):
        self.full_path = path

    def set_driver(self, driver):
        self.driver = driver

    def set_mail_meta(self, **kwargs):
        self.__dict__.update(kwargs)
    


