from fortify.cli import CLI

import os

import fortify.context as context

from fortify.parsing.data_loader import DataLoader
from fortify.inventory.target_manager import TargetManager
from fortify.exporter.export_manager import ExportManager
from fortify.executor.benchmark_executor import BenchmarkExecutor
from fortify.cli.parser import arg_helper as parser
from fortify.utils.logger import logger

class BenchmarkCLI(CLI):
    """
    The scripts to run security benchmarking for fortiga`te againts the desired configuration state
    """
    name = "fortify-benchmark"
    logo = ""

    def initialize_parser(self):
        # usage=f"{self.name} [options] -p [API-KEY] state.yml [state2 ...]"
        description = "Runs Fortify benchmark, benchmark the configuration on the targeted hosts."
        super(BenchmarkCLI, self).initialize_parser(
            # usage=usage,
            desc=description
        )
        self.parser.add_argument(dest="args", metavar="benchmark.yml", type=str, nargs='+', 
                                 help="A file containing list of modules to benchmark on the targeted host(s)")
        
        self.parser.add_argument('-c', '--config', dest="config", metavar='fortify.yml', action="store", 
                                 help="Fortify config file to set application behaviours.")
        
        self.parser.add_argument("-t", "--target-hosts", dest="targets", metavar="targets.yaml", action="store",
                                 help="List of target(s) for benchmark.", required=True)
        
        self.parser.add_argument("-f", "--benchmark-filters", dest="filters", metavar="filters.yaml", action="store",
                                 help="Apply a filter for benchmark using a regex pattern for matching target name")
        
        self.parser.add_argument("-e", "--export", dest="export_config", metavar="exports.yaml", action="store", 
                                 help="Export the benchmark result as defined in the exports.yaml")
        
        self.parser.add_argument("--simple-export", dest="simple_export", metavar="results.json|results.yaml|results.pdf", action="store", 
                                 help="""The path to where the export should be saved, including its filename and extension. 
                                 The extension determines the format that the application will use to export the results""")
        
    def post_process_args(self, options):
        """
        this is where you check CLI arguments.
        Ensure everything is sanitize and as expected, else kill the app.
        """
        options = super().post_process_args(options)
        logger.verbosity = options.verbosity

        try:
            # check if the state file(s) passed is a file
            for filename in options.args:
                if not os.path.exists(filename):
                    raise Exception(f'{filename} file does not exist')
                if not os.path.isfile(filename):
                    raise Exception(f"{filename} argument passed is not a file")
        except Exception as e:
            raise e

        return options
    
    def _cli_prereqs(self):
        """
        Load common utilities
        """
        # Data parser helper
        loader = DataLoader()

        # Inventory management
        # add target sourcess
        bencmark_targets = []
        if context.CLIARGS.targets:
            bencmark_targets.append(context.CLIARGS.targets)
        # add filter sources
        benchmark_filters = []
        if context.CLIARGS.filters:
            benchmark_filters.append(context.CLIARGS.filters)

        inventory = TargetManager(
            loader=loader, 
            target_sources=bencmark_targets,
            filter_sources=benchmark_filters
        )

        benchmark_exports = []
        if context.CLIARGS.export_config:
            benchmark_exports.append(context.CLIARGS.export_config)
        
        exporter = ExportManager(
            loader=loader,
            configs=benchmark_exports
        )

        if context.CLIARGS.simple_export:
            file_path = context.CLIARGS.simple_export
            nw_exporter = exporter.create_exporter_from_file_path(file_path)
            nw_exporter.set_full_path(file_path)
            exporter.set_exporter(nw_exporter)
        
        return loader, inventory, exporter
        
    def run(self):
        """
        Run one or more benchmark to one or more hosts
        """
        super(BenchmarkCLI, self).run()

        # load the inventory and data loader
        loader, inventory, exporter = self._cli_prereqs()

        be = BenchmarkExecutor(
            benchmarks=context.CLIARGS.args,
            loader=loader,
            inventory=inventory,
            exporter=exporter,
        )
        
        result = be.run()

        return result

def main(args=None):
    BenchmarkCLI.cli_execute(args)

if __name__ == "__main__":
    main()