import os
import re

from fortify.parsing.data_loader import DataLoader
from fortify.inventory.target_inventory import TargetInventory
from fortify.inventory.fortigate_host import FortiGateHost
from fortify.inventory.fortimanager_host import FortiManagerHost
from fortify.parsing.data_loader import DataLoader
from fortify.plugins.filter import Filter
from fortify.utils.logger import logger

class TargetManager():
    """Create and manage target host inventories"""
    def __init__(self, loader: DataLoader, target_sources = [], filter_sources = [], parse=True):
        self._loader = loader
        self._inventory = TargetInventory()
        # e.g. targets.yaml
        self.target_sources = target_sources
        # e.g filters.yaml
        self.filter_sources = filter_sources

        if parse:
            # populate target invetory using the given source
            self.parse_targets_sources();
            # apply filters to match host
            self.parse_filter_sources()
    
    def add_target_hosts(self, hosts: list[FortiGateHost]):
        """Add a collection of host to the inventory"""
        for host in hosts:
            self.add_target_host(host)

    def add_target_host(self, host: FortiGateHost):
        """Add a host to the inventory"""
        self._inventory.add_host(host)

    def add_new_target_host(
            self, 
            target_name: str, 
            host_name: str, 
            port: int, 
            api_key: str | None,
            manager: FortiManagerHost | None = None, 
            adom: str | None = None,
        ):
        """Create and add new target host to the inventory"""
        new_target_host = FortiGateHost(
            target_name=target_name,
            host_name=host_name,
            port=port,
            api_key=api_key,
            manager=manager,
            adom=adom
        )

        self._inventory.add_host(new_target_host)

    def get_all_target_host(self):
        """Return all the hosts stored"""
        return self._inventory.get_hosts()
    
    def get_all_target_host_by_pattern(self, pattern: str):
        """Return all the host that match the given pattern"""
        hosts = self.get_all_target_host()
        return [host for host in hosts if re.match(pattern, host.get_target_name())]
    
    def check_source(self, source):
        """Perform check whether the source is actually a file and is exist"""
        r_path = os.path.realpath(source)
        try:
            if not os.path.exists(r_path):
                raise Exception(f"{r_path} file does not exist")
            if not os.path.isfile(r_path):
                raise Exception(f"{r_path} is not a file")
        except Exception as e:
            raise e

    def parse_filter_sources(self):
        """Parse all the filter from the stored list of sources"""
        logger.status(msg="FILTER", status="LOADING", seperation=False)

        for source in self.filter_sources:
            self.check_source(source)
            self.apply_filter_from_file(source)
        
        if self.filter_sources:
            logger.v("OK: No filters are found")
        
    def apply_filter_from_file(self, filter_path: str):
        """Parsed the filters and applied them to each matching hosts"""
        parsed_filter = self._loader.load_from_yaml_file(filter_path)

        for f in parsed_filter["filters"]:
            new_filter = Filter(
                name=f["name"], 
                pattern=f["pattern"], 
                ignore_list=f["ignore"]
            )

            filtered_hosts = self.get_all_target_host_by_pattern(
                pattern=new_filter.pattern
            )

            for host in filtered_hosts:
                new_filter.apply(host)

            logger.v(
                msg=f"OK: [{f["name"]}] applied {len(filtered_hosts)} times"
            )

    def parse_targets_sources(self):
        """Parse all the target from the stored list of sources"""
        logger.status(msg="INVENTORY", status="LOADING", seperation=False)

        for source in self.target_sources:
            self.check_source(source)
            self.parse_from_inventory_file(source)
            logger.v(msg=f"Total targets: {len(self.get_all_target_host())}")
    
    def parse_from_inventory_file(self, invetory_path: str):
        """Parse the target(s) source from a yaml file"""
        # Parse the yaml file
        parsed_data = self._loader.load_from_yaml_file(invetory_path)
        # Loop over the target list and add them to the inventory
        for target in parsed_data["targets"]:
            if target.get("is_manager", False) == True: # if target is a manager
                # create a new fortimanager host
                fm = FortiManagerHost(
                    target_name=target.get("name"),
                    host_name=target.get("host"),
                    port=target.get("port"),
                    username=target.get("username"),
                    password=target.get("password"),
                    auto_login=True,
                )
                # maybe add a check if the adom exist in the fortimanager??
                # before fetching all the firewall info?

                # retrive all firewall from adom(s)
                for adom in target.get("adom"):
                    # get all the firewall from that adom
                    for adom_name, adom_opt in adom.items():
                        firewalls = fm.get_firewalls_from_adom(adom_name)

                        if adom_opt:
                            only_firewalls = adom_opt.get("firewalls", [])
                            if only_firewalls != []:
                                filtered_firewall = fm.filter_firewall_by_name(
                                    firewalls=firewalls, 
                                    filter=only_firewalls
                                )
                                self.add_target_hosts(filtered_firewall)
                        else:               
                            self.add_target_hosts(firewalls)               
            else: # if host is a fortigate
                self.add_new_target_host(
                    target_name=target['name'], 
                    host_name=target['host'], 
                    port=target.get('port', 443),
                    api_key=target.get('api_key'),
                )

        # display information to the user
        total_target = len(parsed_data["targets"])
        logger.vv(
            msg=f"OK: {invetory_path} parsed"
        )
