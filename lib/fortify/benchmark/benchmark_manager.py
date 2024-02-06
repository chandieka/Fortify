import os
import sys

import fortify.context as context

from fortify.parsing.data_loader import DataLoader
from fortify.benchmark import Benchmark
from fortify.plugins.loader import PluginLoader
from fortify.inventory.fortigate_host import FortiGateHost
from fortify.utils.logger import logger

class BenchmarkManager():
    """
    This class hold the lis of benchmark task  
    """
    
    def __init__(self, loader: DataLoader):
        """
        Initialise the benchkmark manager
        """
        self._loader = loader
        self._benchmark_entries = []

        self.file_path = ""
        self.version = ""
        self.name = ""
        self.description = ""

    @staticmethod
    def load(file_path: str, loader: DataLoader, plugin_loader: PluginLoader):
        """
        Return an instance of the benchmark
        """
        b = BenchmarkManager(loader=loader)
        
        b._load_benchmark_data(file_path=file_path, plugin_loader=plugin_loader)
        
        return b
    
    def _load_benchmark_data(self, file_path: str, plugin_loader: PluginLoader):
        """
        parsed the benchmark file and populate the _benchmark_entries list 
        with newly created benchamark.
        """
        filename = os.path.basename(file_path)
        logger.status(msg=f"BENCHMARK TASKS - {file_path}", status="LOADING", seperation=False)

        try:
            # store the full path
            self._file_path = file_path
            # parsed the file
            parsed_data = self._loader.load_from_yaml_file(file_path=file_path)
            # store the metadata
            self.version = parsed_data["version"]
            self.name = parsed_data['name']
            self.description = parsed_data['description']
            # store the selected plugin in the manager
            for benchmark in parsed_data['benchmark']:
                for name, options in benchmark.items():
                    # # get the plugin for the benchmark by its name
                    plugin = plugin_loader.get_plugin(name)
                    plugin_opt = None
                    # check if any option is set
                    if options is not None:
                        plugin_opt = options
                    # create new benchmark
                    new_benchmark = Benchmark(plugin=plugin, options=plugin_opt)
                    # add the new benchmark to the list
                    self._benchmark_entries.append(new_benchmark)
            logger.v(msg=f"OK: Total of {len(self._benchmark_entries)} benchmark(s) task loaded!")
        except Exception as e:
            raise e                

    def get_loader(self):
        return self._loader
    
    def get_benchmarks(self):
        return self._benchmark_entries
    
    def execute_all_to_target(self, target: FortiGateHost):
        """
        Run all the modules to the target host
        Return the result of the module(s)
        """
        logger.status(
            msg=f"{target.get_target_name()}", 
            status="BENCHMARK", 
            seperation=False)
        
        results = []

        for benchmark in self._benchmark_entries:
            filter = benchmark.is_ignore(target)
            if filter:
                benchmark_result = benchmark.get_ignore_result(filter)
            else:
                benchmark_result = benchmark.execute(target)

            logger.benchmark_result(benchmark_result)
            results.append(benchmark_result)
        
        return results
    