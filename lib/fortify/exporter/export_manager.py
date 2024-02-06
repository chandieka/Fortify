import os

from fortify.exporter import Exporter
from fortify.exporter.json_exporter import JSONExporter
from fortify.exporter.yaml_exporter import YAMLExporter
from fortify.exporter.pdf_exporter import PDFExporter
from fortify.serializer import Serializer
from fortify.utils.logger import logger

EXPORT_DRIVER_TYPE = [
    "email",
    "filesystem"
]

class ExportManager():
    """
    """
    def __init__(self, loader, configs: list | None = None):
        self.loader = loader
        self.exporters = []

        if configs:
            self.load_exporter_from_source(configs)

    def create_exporter_from_file_path(self, full_path):
        file_name, file_extension = os.path.splitext(full_path)
        format = file_extension.lower()

        if format == ".json":
            return JSONExporter()
        elif format == ".yaml" or format == ".yml":
            return YAMLExporter()
        elif format == ".pdf":
            return PDFExporter()
        else:
            return JSONExporter()
    
    def set_exporter(self, exporter: Exporter):
        self.exporters.append(exporter)
    
    def load_exporter_from_source(self, configs):
        for conf in configs:
            parsed_config = self.loader.load_from_yaml_file(conf)
            for output in parsed_config.get("outputs", []):
                file_name = output.get("export")
                exporter = self.create_exporter_from_file_path(file_name)

                driver = output.get('driver')
                type = driver.get("type")
                exporter.set_driver(type)
                if type == "filesystem":
                    # Location where to store the benchmark results
                    # can be relative or full path
                    dir_path = driver.get("dir_path")
                    # append it with the filename + extension
                    path = dir_path + file_name
                    # set for export
                    exporter.set_full_path(path)
                elif type == "email":
                    message_meta = driver.get("message")
                    exporter.set_mail_meta(
                        smtp_host=driver.get("hostname"),
                        smtp_port=driver.get("port"),
                        message_subject=message_meta.get("subject"),
                        message_from=message_meta.get("from"),
                        message_to=message_meta.get("to"),
                        message_body=message_meta.get("body"),
                        message_file_name=file_name
                    )

                self.set_exporter(exporter)

    def export(self, data):
        if self.exporters:
            logger.status(
                msg="SAVING BENCHMARK RESULT",
                status="EXPORTING", 
                seperation=False,
            )
            
            serializer = Serializer(data)
            for exporter in self.exporters:
                serilized_data = exporter.export(serializer)
                if exporter.driver == "email":
                    exporter.mail(serilized_data)
                else:
                    exporter.save(serilized_data)
        
        
