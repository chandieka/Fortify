import os

from fortify.exporter import Exporter
from fortify.serializer import Serializer
from fortify.utils.logger import logger

class YAMLExporter(Exporter):
    def export(self, serializer: Serializer):
        """Export the benchmark results"""
        super(YAMLExporter, self).export(serializer)
        logger.display(f"OK: Exporting to YAML", color="light_yellow")
        return serializer.to_yaml()
        
        
