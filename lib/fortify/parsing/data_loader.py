import os
import yaml

class DataLoader():
    """This class is responsible in loading data from a known format."""
    
    def load_from_yaml_file(self, file_path: str) -> dict:
        """load data from a file formmated in YAML"""
        parsed_data = {}
        try:
            if os.path.isfile(file_path):
                with open(file=file_path, mode="+r") as file_stream:
                    try:
                        parsed_data = yaml.safe_load(stream=file_stream)
                    except yaml.YAMLError as exc:
                        raise   
            return parsed_data
        except Exception as e:
            raise e