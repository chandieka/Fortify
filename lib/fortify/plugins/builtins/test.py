import os
import json
import time

from fortify.plugins import FortifyPlugin

class TestPlugin(FortifyPlugin):
    """
    Test plugin class to test the functionality of the plugin system
    """
    _name = "test"
    _option_requirement = dict(
        # var1=dict(type=str, required=True, default="hello"),
        # var2=dict(type=str, required=True, default="word"),
    )
    _description = "This is a test plugin, used it as an example."
        
    def action(self):
        """
        docstring
        """
        super(TestPlugin, self).action()

        time.sleep(1) 

        self._result["status"] = "succeed"

        return self._result
    