from dhcp import dhcp_class, uplink_test, get_isp
from sniffer import *
from hwinfo import hw_info
from db import db_class

class api():
    
    def __init__(self):
        self.dhcp = dhcp_class()
        self.db = db_class()
        self.hwinfo = hw_info()
        self.sniffer = sniffer_class()

        # setting up database AND matching sniffers db_path to same as dbs BECAUSE writing to db happens in sniffers packet hanlder DUE TO scapys sniffer arcitecture 
        self.db.init_db()
        self.sniffer.db_path =self.db.db_path
        
        # probably stuff still needs to happen here


    def trigger_dhcp(self):
        """
        Triggers DHCP.
        """
        self.dhcp.build_dhcp_discover()
        self.dhcp.offers = self.dhcp.send_packet(self.dhcp.discover)
        self.dhcp.build_dhcp_request()
        self.dhcp.ack = self.dhcp.send_packet(self.dhcp.request)
        self.dhcp.bind_new_ip()


        # print(type(ack[DHCP].options))         # type: ignore
        # print(ack[DHCP].options)                # type: ignore

    def get_network_info():
        """
        Tests if there is an uplink and if so which via which ISP.

        :retruns: 
        """
        net_info = None
        if uplink_test():
            
            get_isp()
        else:
            net_info

    def get_packet_list(self):
        packet_list = []
        return packet_list
    
my_api = api()