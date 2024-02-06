import os
from fortify.inventory.fortigate_host import FortiGateHost

class TargetInventory():
    """
    this class is responsible as a holder for the list of hosts
    """
    def __init__(self):
        """Initialize target host inventory"""
        self._target_hosts = []

    def add_host(self, host: FortiGateHost):
        """Add a new target to list of target hosts"""
        self._target_hosts.append(host)

    def get_hosts(self):
        """Return all the stored target"""
        return self._target_hosts
    
    def get_total_hosts(self):
        """Return the total amount of host stored"""
        return len(self._target_hosts)