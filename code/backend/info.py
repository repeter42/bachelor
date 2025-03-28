from scapy.all import *

class info_class():

    def __init__(self, timeout_in = 3, isListening_in = True):
        self.timeout = timeout_in
        self.isListening = isListening_in   # whether or not program is listening fot traffic
        self.nicInfo = self.set_nicInfo()

    def set_nicInfo(self):
        iface_list = get_if_list()
        for iface in iface_list:
            if iface.startswith(("en", "eth")):
                nicName = iface
                strMac = get_if_hwaddr(iface)       # this is only a string of the mac address ... not a byte format which is required by scapy
                strMac =  strMac.replace(":", "")
                byteMac = bytes.fromhex(strMac)
                bytecount = len(byteMac)
                while len(byteMac) < 6:
                     byteMac = b'\x00' + byteMac
                
                return (nicName, byteMac) 

    def get_nicInfo(self):
        """
        :returns: nicInfo: [0]name, [1]mac
        :rtype: (str, str)
        """
        return self.nicInfo

    # # getter and setter are there now
    # def set_timeout(self, in_timeout):
    #     self.timeout = in_timeout

    # def get_timeout(self):
    #     return self.timeout

my_info = info_class()