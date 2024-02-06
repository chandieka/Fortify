import os

from fortify.utils.logger import logger
from fortify.inventory.fortigate_host import FortiGateHost
from fortify.errors import FortifyPluginLoaderErrors

class Benchmark():
    def __init__(self, plugin, options = {}):
        """
        This class is responsible as a wrapper to execute the stored plugin 
        with the options given toward the selected target. 
        """
        self._plugin = plugin

        if options is not None:
            self._options = options
        else:
            self._options = dict()

        # do pre check if the arguement met the requirement
        self.check_opt_requirement(self._options, self._plugin.get_opt_type())
    
    def execute(self, target: FortiGateHost):
        """
        Execute the plugin on the target host
        """
        return self._plugin.execute_action(
            options=self._options, 
            target_host=target)
    
    def get_plugin_name(self):
        return self._plugin.get_name();

    def check_opt_requirement(self, options, requirements):
        """
        Check if the option passed from the benchmark file meet the requirement of the plugin
        TODO: 
            Add message to the Exception or replace with custom Exception
        """
        try:
            new_opt = dict()
            # Check if the option is None
            for option_name, option_requirement in requirements.items():
                # not empty or null
                if not options:
                    # if no option specified, and default value is specified, used it
                    if option_requirement.get("required", False) and "default" in option_requirement:
                        new_opt[option_name] = option_requirement["default"];
                else:
                    # Check if the option_name exist in the passed options
                    if option_name not in options:
                        # is required, and no default set, raise exception 
                        if option_requirement.get("required", False):
                            raise FortifyPluginLoaderErrors(
                                f"'{self._plugin.get_name()}' plugin require '{option_name}' as a plugin option"
                            )
                        
                        # if default value is specified, used it
                        if "default" in option_requirement:
                            new_opt[option_name] = option_requirement["default"]
                    else:
                        # check type
                        if not isinstance(options[option_name], option_requirement["type"]):
                            raise FortifyPluginLoaderErrors(
                                f"'{self._plugin.get_name()}' plugin require '{option_name}' option with value that have '{option_requirement['type']}' type not '{type(options[option_name])}'"
                            )
                        
                        # if option is set, but is none, check for default
                        if options[option_name] is None and "default" in option_requirement:
                            new_opt[option_name] = option_requirement["default"]
                        else:
                            new_opt[option_name] = options[option_name]
            # not empty or null
            if not options:
                # is not empty, update
                options.update(new_opt)
            else:
                # is empty, replace
                options = new_opt
        except Exception as e:
            raise e

    def is_ignore(self, target: FortiGateHost):
        # only need to hit once
        for filter in target.filters:
            if filter.check(self._plugin):
                return filter
        else:
            return False
    
    def get_ignore_result(self, target):
        return self._plugin.get_ignore_result(target)
