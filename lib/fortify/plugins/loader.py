import os
import sys
import importlib
import importlib.util
import inspect

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from fortify.utils.logger import logger
from fortify.plugins import FortifyPlugin

class PluginLoader():
    """
    PluginLoader class is responsible in loading and interfacing with load plugins by using their name or FQN
    """
    def __init__(self, load_builtins=True):
        """Initialize the plugins loader"""
        self.plugins = {}

        if load_builtins:
            self.load_builtins()
    
    def _get_builtin_plugins_filename(self):
        """Return all the filename for all builtin plugins"""
        plugin_filenames = []

        # define this file working directory
        fwd = os.path.dirname(__file__)
        dir_path = os.path.realpath(f"{fwd}/builtins")

        # get all the filenames of the builtin plugins
        plugin_filenames += self.get_plugins_filename_from_path(dir_path)

        return plugin_filenames
    
    def get_plugins_filename_from_path(self, path: str):
        """Return all the plugin filename from a path"""
        plugin_filenames = []
        
        try:
            r_path = os.path.realpath(path)
            if not os.path.exists(r_path) and not os.path.isfile(r_path):
                raise Exception(f"{r_path} does not exist")
            if os.path.isdir(r_path):
                for file_name in os.listdir(r_path):
                    if file_name.endswith(".py") and os.path.isfile(f"{r_path}/{file_name}"):
                        plugin_filenames.append(file_name.split('.')[0])
        except Exception as e:
            raise e
        return plugin_filenames
    
        
    def load_builtins(self):
        """
        Load all builtin plugin object pair with its plugin name
        
        TODO:
            - Replace module name with FQN (Fully qualified name), ex: fortify.builtins.my_plugin
              this would help later when loading from user define plugin(s)
        """
        logger.status(msg="BUILTIN PLUGINS", status="LOADING", seperation=False)
        # base path of builtin modules
        module_path = "fortify.plugins.builtins"
        # get all modules filename
        plugin_filenames = self._get_builtin_plugins_filename()
        # iterate every plugin filename in the fortify.plugins.builtins directory
        for file_name in plugin_filenames:
            plugin = importlib.import_module(f"{module_path}.{file_name}")
            for name, obj in inspect.getmembers(plugin):
                if self.check_plugin_preq(obj):
                    # should be replace with obj.get_name()
                    self.add_plugin(obj.get_name(), obj)
        logger.v(msg=f"OK: Total of {len(self.plugins)} plugin(s) loaded!")
        
    def load_plugin_from_path(self, plugin_file_path: str):
        """load a plugin from the given full path of the file"""
        try:
            r_path = os.path.realpath(plugin_file_path)
            
            if not os.path.exists(r_path) and not os.path.isfile(r_path):
                raise Exception(f"{r_path} does not exist")

            # get the filename without extension
            plugin_name = os.path.basename(r_path).split('.')[0]

            # Load plugin from a file path
            mod_spec = importlib.util.spec_from_file_location(plugin_name, r_path)
            plugin = importlib.util.module_from_spec(mod_spec)
            mod_spec.loader.exec_module(plugin)

            for name, obj in inspect.getmembers(plugin):
                if self.check_plugin_preq(obj):
                    # should be replace with obj.get_name()
                    self.add_plugin(obj.get_name(), obj)
        except Exception as e:
            raise e

    def _is_plugin_in_list(self, plugin) -> bool:
        """Check if the plugin is in the chache list"""
        set_list = set(self.plugins)
        if plugin in set_list:
            return True
        else:
            return False
    
    def check_plugin_preq(self, obj) -> bool:
        """check if the object is a fortify plugin"""
        plugin_interface_fqn = "fortify.plugins"

        if not inspect.isclass(obj):
            return False
        elif not issubclass(obj, FortifyPlugin):
            return False
        elif obj.__module__ == plugin_interface_fqn:
            return False
        elif self._is_plugin_in_list(obj):
            return False
        else:
            return True
    
    def add_plugin(self, plugin_key, plugin):
        """Add plugin to the cache list"""
        self.plugins[plugin_key] = plugin
    
    def get_plugin(self, plugin_key):
        """Return a plugin by it's key"""
        try:
            # will cause error if there is no plugin with the same key
            if plugin_key in self.plugins:
                return self.plugins[plugin_key]
            else:
                raise Exception(f"{plugin_key} plugin does no exist in the builtins list")
        except Exception as e:
            raise e

    