from network import dhcp_class, uplink_test, get_isp
from sniffer import *
from backend.info import info
from db import db_class

class api():
    
    # INIT
    def __init__(self):
        self.dhcp = dhcp_class()
        self.db = db_class()
        self.info = info()
        self.sniffer = sniffer_class()
        self.error = None       # when error occurs and gets caught, error is written here 

        # setting up database AND matching sniffers db_path to same as dbs BECAUSE writing to db happens in sniffers packet hanlder DUE TO scapys sniffer arcitecture 
        self.db.init_db()
        self.sniffer.db_path =self.db.db_path
        
        # probably stuff still needs to happen here

    # HARDWARE
    def init_hw(self):
        self.info.set_nicInfo()

    # DHCP
    def trigger_dhcp(self):
        """
        Triggers DHCP and sets the messages.
        """
        self.dhcp.build_dhcp_discover()
        self.dhcp.offers = self.dhcp.send_packet(self.dhcp.discover)
        if self.dhcp.arp_ping():
            self.error = "ARP test: IP is taken"
            return 
        self.dhcp.build_dhcp_request()
        self.dhcp.ack = self.dhcp.send_packet(self.dhcp.request)
        self.dhcp.bind_new_ip()


        # print(type(ack[DHCP].options))         # type: ignore
        # print(ack[DHCP].options)                # type: ignore

    # NETWORK
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

    # DATABASE
    def get_packet_list(self, query_in):
        packet_list = []
        
        self.db.get_packets(query_in)

        self.sniffer.newPacket = False
        return packet_list
    
    # SNIFFER
    def is_new_packet_sniffed(self):
        return self.sniffer.newPacket

    def set_isListening(self, isListening_in):
        """
        Sets the variable isListening of api.sniffer and if True also starts listening
        """
        self.sniffer.isListening = isListening_in
        if self.sniffer.isListening:
            self.sniffer.start_sniffing_traffic()
    
    def get_isListening(self):
        return self.sniffer.isListening

    
my_api = api()