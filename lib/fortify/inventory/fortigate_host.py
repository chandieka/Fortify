from fortify.inventory.host import Host

class FortiGateHost(Host):
    """
    This class represent a single target host.
    """
    def __init__(
            self, 
            target_name: str, 
            host_name: str | None = None,
            port: int | None = None,
            api_key: str | None = None,
            manager = None,
            adom: str | None = None, 
            id=True,
        ):
        """
        Initialize a new target host
        """
        super(FortiGateHost, self).__init__(
            target_name, 
            host_name,
            port,
            id,
        )

        self._api_key = api_key
        self.manager = manager
        self.adom = adom
        self.filters = []

    def get_manager_fqdn(self):
        """return this host manager fully qualified domain name (FQDN)"""
        if self.manager:
            host = self.manager.get_host_name()
            port = self.manager.get_host_port()
            return f"https://{host}:{port}"
        else:
            return False
    
    def has_manager(self):
        """Check whether this host is managed by a fortimanager"""
        return self.manager is not None
    
    def get_api_key(self):
        """Return the API key of this Fortigate"""
        return self._api_key
    
    def add_filter(self, filter):
        """Append filter to the filter list"""
        self.filters.append(filter)

    def add_filters(self, filters):
        """Add a sets of filter to the filter list"""
        for filter in filters:
            self.add_filter(filter)

    