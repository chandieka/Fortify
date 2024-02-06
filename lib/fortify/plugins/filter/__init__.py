from fortify.plugins import FortifyPlugin
from fortify.inventory.fortimanager_host import FortiGateHost

class Filter():
    """The class the represent the plugin filter"""
    def __init__(
            self, 
            name: str, 
            pattern: str, 
            ignore_list: list[str]
        ):

        self.name = name
        self.pattern = pattern
        self.ignore_list = ignore_list

    def apply(self, host: FortiGateHost):
        """Add this filter object to the host filter list"""
        host.add_filter(self)

    def check(self, plugin: FortifyPlugin):
        """Check if the plugin is set to ignored"""
        return plugin.get_name() in self.ignore_list