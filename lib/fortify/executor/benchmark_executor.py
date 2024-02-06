from pathlib import Path  
from datetime import datetime

import fortify.context as context

from fortify.utils.logger import logger
from fortify.plugins.loader import PluginLoader
from fortify.parsing.data_loader import DataLoader
from fortify.inventory.target_manager import TargetManager
from fortify.benchmark.benchmark_manager import BenchmarkManager
from fortify.exporter.export_manager import ExportManager
# from fortify.serializer.benchmark_exporter import BenchmarkExporter

class BenchmarkExecutor():
    """
    This is the primary class for executing the benchmarks.
    """
    def __init__(self, benchmarks, loader: DataLoader, inventory: TargetManager, exporter: ExportManager):
        """
        Initialize the executor for benchmarking
        """
        self._benckmarks = benchmarks
        self._loader = loader
        self._inventory = inventory
        self._exporter = exporter

    def run(self):
        """
        Run the benchmark against the targeted hosts.
        """
        try:
            # load plugins here?
            pl = PluginLoader(load_builtins=True)
            # iterate the benchmark files
            for benchmark in self._benckmarks:
                # Create the manager for the benchmarks
                bm = BenchmarkManager.load(
                    file_path=benchmark, 
                    loader=self._loader,
                    plugin_loader=pl)
                
                data = {
                    "benchmark": Path(benchmark).name,
                    "date": datetime.now().isoformat(),
                    "results": []
                }

                results = data.get("results")
                for target in self._inventory.get_all_target_host():
                    benchmark_result = bm.execute_all_to_target(target)
                    results.append({
                        "target": target.target_name,
                        "plugin_output": benchmark_result,
                    })

                logger.recap(results)

                self._exporter.export(data)
                
        except Exception as e:
            raise e
        
        return 1