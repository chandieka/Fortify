import os
import json
import yaml
import pdfkit

import fortify.plugins as fp
from jinja2 import Environment, FileSystemLoader

class Serializer():
    """
    This class is used to serilized python dictionary into a storable format.
    Such as: JSON, YAML, and PDF.
    """
    def __init__(self, data: list | dict):
        """Initialize the serializer class"""
        self.data = data

    def _create_or_update_file_content(self, file_path: str, file_content):
        """Add content to a new or existing file"""
        if type(file_content) == str:
            with open(file=file_path, mode="w") as file:
                file.writelines(file_content)
        else:
            with open(file=file_path, mode="wb") as file:
                file.write(file_content)

    def to_yaml(self):
        """Serialize the data to YAML format"""
        return yaml.dump(self.data)

    def to_json(self):
        """Serialize the data to JSON format"""
        return json.dumps(self.data, indent=4)

    def to_pdf(self):
        """Serialize the data to PDF format"""
        summaries = []
        for result in self.data.get("results"):
            summary = self.get_summary(result.get("plugin_output"), result.get("target"))
            summaries.append(summary)

        try:
            fwd = os.path.dirname(__file__)
            template_dir = f"{fwd}/templates/"
            fsl = FileSystemLoader(template_dir)

            env = Environment(
                loader=fsl
            )
            template = env.get_template("basic.html.jinja")
            parsed_template = template.render(
                benchmarks=self.data.get("results"),
                summaries=summaries,
                benchmark_file=self.data.get("benchmark"),
                date=self.data.get("date"),
            )

            pdf_content =  pdfkit.from_string(
                input=parsed_template,
            )
            return pdf_content
        except Exception as e:
            raise e
        
    def save_to_path(self, data, path: str):
        self._create_or_update_file_content(path, data)

    def _filter_data(self, criteria: list):
        """
            TODO: add option to filter what to see from the data in the output
        """
        pass

    def get_summary(self, benchmark_result, host_name):
        total_run = len(benchmark_result)
        total_success = len([br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_SUCCESS])
        total_fail = len([br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_FAIL])
        total_skip = len([ br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_SKIPPED])
        total_ignore = len([br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_IGNORE])
        rating = f"{round((total_success/total_run)*100)}%" if total_success > 0 else "0%"

        return {
            "device_name": host_name,
            "total_run": total_run,
            "total_success": total_success,
            "total_fail": total_fail,
            "total_skip": total_skip,
            "total_ignore": total_ignore,
            "rating": rating
        }