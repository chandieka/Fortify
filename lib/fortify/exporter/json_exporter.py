import os

from fortify.exporter import Exporter
from fortify.serializer import Serializer
from fortify.utils.logger import logger

class JSONExporter(Exporter):
    def export(self, serializer: Serializer):
        """Export the benchmark results"""
        super(JSONExporter, self).export(serializer)
        logger.display(f"OK: Exporting to JSON", color="light_yellow")
        return serializer.to_json()
