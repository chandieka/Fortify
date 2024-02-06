import os
import sys
import logging
import pprint
import json

from datetime import datetime
from termcolor import colored, cprint

import fortify.plugins as fp
from fortify.utils.color import COLOR_PALETTE

class Logger():
    """
    This class is resposible at displaying output to the stdout
    """
    def __init__(self, verbosity: int = 0):
        """Initialize the logging class"""
        self.verbosity = verbosity # will be used later for determining display, log, error level
    
    def display(
        self, msg: str, 
        color: str | None = None,
        stderr: bool = False,
        log_only: bool = False,
        newline: bool = True):
        """
        Display a message to the user.

        due note: "msg" arg need to be in Unicode format to prevent UnicodeError traceback.
        """
        if not isinstance(msg, str):
            raise TypeError(f"Display message must be a str, not: {msg.__class__.__name__}")
        
        if not log_only:
            has_new_line = msg.endswith(u"\n")
            if has_new_line:
                # remove new line
                msg2 = msg[:-1]
            else:
                msg2 = msg

            if has_new_line or newline:
                msg2 = f"{msg2}\n"

            if color and color in COLOR_PALETTE:
                msg2 = colored(msg2, color)

            if stderr:
                display_obj = sys.stderr
            else:
                display_obj = sys.stdout
            
            display_obj.write(msg2)
        
    def status(self, msg: str, status = "STATUS", seperation=True):
        """Display status message to the user"""
        without_color_msg = f"[{status}] {msg} "

        if sys.stdout.isatty():
            column, lines = os.get_terminal_size()  
            filler = colored("*" * (column - len(without_color_msg)), "magenta")
        else:
            filler = ""
        
        color_status = colored(status, "yellow")
        with_color_msg = f"[{color_status}] {msg} "

        if sys.stdout.isatty():
            newline = "\n"
        else:
            newline = "\n"
            
        self.display(msg=f"{newline}{with_color_msg}{filler}")

        if seperation:
            self.display(msg="")

    def banner(self, app_name: str):
        """Print the application banner to the user"""
        column, lines = os.get_terminal_size()
        filler = "*" * column
        filler = colored(filler, "yellow")

        self.display(msg=f"{filler}")
        self.display(msg=f"{app_name}")
        self.display(msg=f"{filler}")

    def clean_tty(self):
        """clear or cls the current terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def pprint(self, msg: str):
        pp = pprint.PrettyPrinter(indent=1, width=1)
        pp.pprint(msg)  

    def benchmark_result(self, result):
        """
        display simple benchmark result to stdout
        """
        if result.get("status") == fp.PLUGIN_STATUS_SKIPPED:
            status = "SKIPPED"
            color = "light_blue"
        elif result.get("status") == fp.PLUGIN_STATUS_WARNING:
            status = "WARNING"
            color = "red"
        elif result.get("status") == fp.PLUGIN_STATUS_SUCCESS:
            status = "PASSED"
            color = "light_yellow"
        elif result.get("status") == fp.PLUGIN_STATUS_IGNORE:
            status = "IGNORE"
            color = "light_red"
        else:
            status = "FAILED"
            color = "red"
            
        if self.verbosity <= 0:
            msg = f"{status}: [{result['plugin_name']}]"
        elif self.verbosity <= 1:
            plugin_message = json.dumps(dict(plugin_message=result['message']), indent=4)
            msg = f"{status}: [{result['plugin_name']}] => {plugin_message}"
        elif self.verbosity <= 2:
            msg = f"{status}: [{result['plugin_name']}]"
        elif self.verbosity <= 3:
            msg = f"{status}: [{result['plugin_name']}]"
        else:
            msg = f"{status}: [{result['plugin_name']}] => {json.dumps(result, indent=4)}"

        self.display(msg=msg, color=color)
            
    def benchmark_summary(self, host_name, benchmark_result):
        """Show the summary of the benchmark"""
        total_run = len(benchmark_result)
        total_succeed = len([br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_SUCCESS])
        total_failed = len([br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_FAIL])
        total_skipped = len([ br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_SKIPPED])
        total_ignore = len([br for br in benchmark_result if br["status"] == fp.PLUGIN_STATUS_IGNORE])
        rating = f"{round((total_succeed/total_run)*100)}%" if total_succeed > 0 else "0%"

        self.display(
            msg=f"{host_name:<25}{total_run:<15}{total_succeed:<15}{total_failed:<15}{total_skipped:<15}{total_ignore:<15}{rating:<15}",
            color="light_yellow",
        )

    def recap(self, results):
        """Show the benchmark recap"""
        self.status("RECAP", "FINISHED", seperation=False)
        
        column_header = "{:25}{:15}{:15}{:15}{:15}{:15}{:15}".format(
            "Host Name", "Total check", "Success", "Failed", "Skipped", "Ignore", "Compliance rating"
        )
        self.display(
            msg=column_header,
            color="light_yellow",
            newline=True,)
        
        for result in results:
            self.benchmark_summary(result.get("target"), result.get("plugin_output"))
        
    def verbose(self, msg: str, caplevel: int = 2):
        if self.verbosity > caplevel:
            self.display(msg, color="light_yellow")

    def v(self, msg: str):
        return self.verbose(msg, caplevel=0)
    
    def vv(self, msg: str):
        return self.verbose(msg, caplevel=1)
    
    def vvv(self, msg: str):
        return self.verbose(msg, caplevel=2)
    
    def vvvv(self, msg: str):
        return self.verbose(msg, caplevel=3)
    
    def vvvvv(self, msg: str):
        return self.verbose(msg, caplevel=4)
    
logger = Logger()

def init_global_logger(new_logger):
    global logger
    logger = new_logger    
