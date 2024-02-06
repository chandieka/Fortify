import os

from fortify.exporter import Exporter
from fortify.serializer import Serializer
from fortify.utils.logger import logger

class PDFExporter(Exporter):
    def export(self, serializer: Serializer):
        """Export the benchmark results"""
        super(PDFExporter, self).export(serializer)
        logger.display(f"OK: Exporting to PDF", color="light_yellow")
        return serializer.to_pdf()