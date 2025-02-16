import scapy
from scapy.all import *

class hw_info():
    """
    This class is supposed to be a singelton like object in which settings are saved and accessed
    """

    def __init__(self, in_timeout=2, in_isListening=True):
        self.timeout = in_timeout
        self.isListening = in_isListening
        self.nicInfo = self.set_nicInfo()
        self.whichFunction = None   # for debugging purposes


    def set_nicInfo(self):
        iface_list = get_if_list()
        for iface in iface_list:
            if iface.startswith(("en", "eth")):
                nicName = iface
                nicMac = get_if_hwaddr(iface)
                return (nicName, nicMac) 
    
    def get_nicInfo(self):
        return self.nicInfo


    def set_timeout(self, in_timeout):
        self.timeout = in_timeout
    
    def get_timeout(self):
        return self.timeout


    def set_isListening(self, in_isListening):
        self.isListening = in_isListening

    def get_isListening(self):
        return self.isListening
    


my_hw_info = hw_info()