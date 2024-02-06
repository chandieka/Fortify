from abc import ABC, abstractmethod

PLUGIN_STATUS_SUCCESS = 0
PLUGIN_STATUS_FAIL = 1
PLUGIN_STATUS_SKIPPED = 2
PLUGIN_STATUS_WARNING = 3
PLUGIN_STATUS_IGNORE = 4

PLUGIN_SUCCESS_MESSAGE = "All criteria is properly configured"

class FortifyPlugin(ABC):
    """
    Base class for all plugin derivative
    """
    # subclass need to update these variables to their desired value
    _name = "fortify_plugin"
    # this dictionary will be used to check the inputted options in the benchmark.yml
    _option_requirement = dict()
    _description = "This is a base FortifyPlugin description"

    def __init__(self):
        """
        Initialize the plugins.
        """
        self._options = {}

    def load_preq(self, options, target_host):
        """
        Subclass can implement this class.
        here you can make checks, changes, or whatever with the options & target_host.
        """
        self._target_host = target_host
        self._options = options
            
    @abstractmethod
    def action(self):
        """
        Subclass must implement this class.
        Main block of code where you can put your plugin logic here.
        """
        self._result = {
            "plugin_name": self._name,
            "description": self._description,
            "options": self._options,
            "status": PLUGIN_STATUS_FAIL,
            "is_compliance": False,
            "message": [],
            "request_response": [],
        }
    
    @classmethod
    def execute_action(cls, options, target_host):
        """
        Interface to execute the plugin 
        """
        mod = cls()
        mod.load_preq(options=options, target_host=target_host)
        result = mod.action()

        return result
    
    @classmethod
    def get_name(cls) -> str:
        """
        return the plugin name
        """
        return cls._name
    
    @classmethod
    def get_opt_type(cls) -> dict:
        """
        return the this plugin meta options
        """
        return cls._option_requirement
    
    @classmethod
    def get_ignore_result(cls, filter) -> dict:
        return {
            "plugin_name": cls._name,
            "description": cls._description,
            "status": PLUGIN_STATUS_IGNORE,
            "message": [
                f"Set to ignore by {filter.name} filter"
            ],
            "request_response": [],
        }
