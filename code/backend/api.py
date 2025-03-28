from network import dhcp_class, test_uplink, test_isp, test_carrier, dummy_test_uplink, test_portal
from sniffer import sniffer_class
from backend.info import info_class
from db import db_class
import multiprocessing

class api_class():

    # INIT
    def __init__(self):
        self.info = info_class()
        self.db = db_class()
        self.dhcp = dhcp_class()
        self.sniffer = sniffer_class()
        self.process_manager = multiprocessing.Manager()
        self.sniffer.isListening = self.process_manager.Value("b", True)    # sniffer is set to True
        self.error = None       # when error occurs and gets caught, error is written here 

        # setting up database AND matching sniffers db_path to same as dbs BECAUSE writing to db happens in sniffers packet hanlder DUE TO scapys sniffer arcitecture 
        self.db.init_db()
        self.sniffer.db_path =self.db.db_path
        self.info.set_nicInfo()
        
        # probably stuff still needs to happen here

    def get_error(self):
        """
        if error
        """
        return self.error

    # HARDWARE
    # maybe not needed as i may just spawn new api instance for new ethport to test
    def init_hw(self):
        self.info.set_nicInfo()

    def set_timeout(self, timeout_in):
        # maybe later implementation for manually set timeout by user
        self.info.timeout = timeout_in


    # DHCP
    def test_dhcp(self):
        """
        Triggers DHCP and sets the messages.
        
        :rtype: bool
        :returns: TRUE: if succesfully aquiered IP; FALSE: IP not aquiered 
        """
        try:
            self.dhcp.build_dhcp_discover()
            self.dhcp._offers = self.dhcp.send_packet(self.dhcp._discover)
            if self.dhcp.arp_ping():
                self.error = "ARP test: IP is taken" 
                print(self.error)
            self.dhcp.build_dhcp_request()
            self.dhcp._ack = self.dhcp.send_packet(self.dhcp._request)
            self.dhcp.bind_new_ip()
        except:
            return False
        return True
        # print(type(ack[DHCP].options))         # type: ignore
        # print(ack[DHCP].options)                # type: ignore

    def get_dhcp_info(self):
        """
        Parses api_dhcp object.

        :rtype: str
        :returns: dhcp info from dhcp_obj (excluding dhcp packets)
        """
        my_dhcp = self.dhcp.__dict__.items()
        dhcp_info = "DHCP INFO\n"
        for dhcp_attr, dhcp_value in my_dhcp:
            # "_" indicates a scapy packet or list of -> to big to properly display (could be commented out if so desired)
            if str(dhcp_attr).startswith("_"):
                continue
            value_str = ""
            # filtering for lists so that they may be printet properly
            if dhcp_attr == "offers":
                for offer in dhcp_value:
                    value_str = value_str + str(offer) + "; "
            if dhcp_attr == "options":
                print(dhcp_value)
                for option_value_pair in dhcp_value:
                    if option_value_pair == "end":
                        value_str = value_str + option_value_pair
                        break
                    value_str = value_str + str(option_value_pair[0]) + ": " + str(option_value_pair[1]) + "; "
            dhcp_info = dhcp_info + str(dhcp_attr) + ": " + str(dhcp_value) + "\n"
        # print("breakpoint")
        return dhcp_info


    # NETWORK
    def test_network(self):
        """
        Tests if there is an uplink and if so which via which ISP.
        
        :returns: network information 
        :rtype: str
        """
        tests = ["FAILED", "FAILED", "NO PORTAL", "FAILED", "FAILED"]

        if test_carrier():
            tests[0] = "SUCCESSFUL"
        else:
            return self.__get_net_info_str(tests)
        if self.test_dhcp():
            tests[1] = "SUCCESSFUL"
        else:
            return self.__get_net_info_str(tests)
        if test_portal():
            tests[2] = "PORTAL"
        else:
            return self.__get_net_info_str(tests)
        # if test_uplink():
        if dummy_test_uplink():
            tests[3] = "SUCCESSFUL"
        else:
            return self.__get_net_info_str(tests)
        try:
            isp = test_isp()
            tests[4] = isp[1] + "; " + isp[0]
        except:
            return self.__get_net_info_str(tests)
        
        return self.__get_net_info_str(tests)

    def __get_net_info_str(self, tests_in):
        """
        internal funtion to get the correct network info string

        :param tests_in: network tests (carrier, dhcp, captive portal, uplink, isp)
        :type tests_in: [str]*5  
        :returns: merged network test info
        :rtype: str
        """
        net_info = f"""
        Physical Carrier Test: {tests_in[0]}
        IP assigned: {tests_in[1]}
        Capitve Portal Test: {tests_in[2]}
        Uplink Test: {tests_in[3]}
        Internet Srvice Provider: {tests_in[4]}
        """
        return net_info


    # DATABASE
    def get_packet_list(self, query_in):
        """
        STILL NEEDS TO BE DONE
        """
        packet_list = []
        
        self.db.get_packets(query_in)

        self.sniffer.newPacket = False
        return packet_list

    def clear_packets(self):
        """
        Deletes all sniffed packets. Let's go Bobby Tabels #xkcd.
        """
        self.db.drop_table()
        self.db.init_db()


    # SNIFFER
    def is_new_packet_sniffed(self):
        """
        PROBABLY UNCESSERAY
        """
        return self.sniffer.newPacket

    def set_write_to_pcap(self, write_to_pcap_in):
        """
        :type write_to_pcap_in: bool
        :param write_to_pcap_in: write traffic to pcap file
        """
        self.sniffer.write_to_pcap = write_to_pcap_in

    def get_writing_to_pcap(self):
        return self.sniffer.write_to_pcap

    def start_sniffing(self):
        """
        Starts sniffing and sets the abort variable api_sniffer.isListening to True
        """
        self.sniffer.isListening.value = True
        self.sniffer.start_sniffing_traffic()

    def stop_sniffing(self):
        """
        Stopps sniffing and sets the abort variable api_sniffer.isListening to False.
        After next packet is sniffed, and abort variable gets checkt, sniffing stopps.
        """
        self.sniffer.isListening.value = False

    def get_isListening(self):
        """
        Returns sniffing abort variable to check whether or not is sniffing now.
        :returns: isListening
        :rtype: bool
        """
        return self.sniffer.isListening.value

