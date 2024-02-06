import os
import uuid

from abc import ABC

from fortify.utils.logger import logger

class Host(ABC):
    """this is the base class for the any host"""
    def __init__(
            self, 
            target_name: str, 
            host_name: str | None = None,
            port: int | None = None,
            id=True,
        ):
        """Initialize a new target host"""
        self.target_name = target_name
        self.host_name = host_name
        self.port = port

        self._id = None
        if id:
            self._id = uuid.uuid1()

    def get_target_name(self):
        """return this host name representation"""
        return self.target_name

    def get_host_name(self):
        """return this host ip address"""
        return self.host_name
    
    def get_host_port(self):
        """return this host port"""
        return self.port