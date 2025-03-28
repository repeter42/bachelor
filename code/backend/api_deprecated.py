from network import dhcp_class, test_uplink, test_isp, test_carrier, test_portal, dummy_test_uplink
from sniffer import sniffer_class
from info import info_class
from db import db_class
import threading


# ERROR
error = None       # when error occurs and gets caught, error is written here 
def get_error():
    return error


# HARDWARE
def init_hw():
    api_info.set_nicInfo()

def set_timeout(timeout_in):        # in case of later implementaions, so that the timeout may be set.
    api_info.timeout(timeout_in)


# DHCP
def test_dhcp():
    """
    Triggers DHCP and sets the messages.
    
    :rtype: bool
    :returns: TRUE: if succesfully aquiered IP; FALSE: IP not aquiered 
    """
    try:
        api_dhcp.build_dhcp_discover()
        api_dhcp._offers = api_dhcp.send_packet(api_dhcp._discover)
        if api_dhcp.arp_ping():
            error = "ARP test: IP is taken" 
            print(error)
        api_dhcp.build_dhcp_request()
        api_dhcp._ack = api_dhcp.send_packet(api_dhcp._request)
        api_dhcp.bind_new_ip()
    except:
        return False
    return True
    # print(type(ack[DHCP].options))         # type: ignore
    # print(ack[DHCP].options)               # type: ignore

def get_dhcp_info():
    """
    Parses api_dhcp object.

    :rtype: str
    :returns: dhcp info from dhcp_obj (excluding dhcp packets)
    """
    my_dhcp = api_dhcp.__dict__.items()
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
def test_network():
    """
    Tests if there is an uplink and if so which via which ISP.
    
    :returns: network information 
    :rtype: str
    """
    tests = ["FAILED", "FAILED", "NO PORTAL", "FAILED", "FAILED"]

    if test_carrier():
        tests[0] = "SUCCESSFUL"
    else:
        return __get_net_info_str(tests)
    if test_dhcp():
        tests[1] = "SUCCESSFUL"
    else:
        return __get_net_info_str(tests)
    if test_portal():
        tests[2] = "PORTAL"
    else:
        return __get_net_info_str(tests)
    # if test_uplink():
    if dummy_test_uplink():
        tests[3] = "SUCCESSFUL"
    else:
        return __get_net_info_str(tests)
    try:
        isp = test_isp()
        tests[4] = isp[1] + "; " + isp[0]
    except:
        return __get_net_info_str(tests)
    
    return __get_net_info_str(tests)

def __get_net_info_str(tests_in):
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
def get_packet_list(query_in):
    packet_list = []
    
    api_db.get_packets(query_in)

    api_sniffer.newPacket = False
    return packet_list

def clear_packets():
    """
    Deletes all sniffed packets. Let's go Bobby Tabels #xkcd.
    """
    api_db.drop_table()
    api_db.init_db()


# SNIFFER
def is_new_packet_sniffed():
    return api_sniffer.newPacket

def set_write_to_pcap(write_to_pcap_in):
    """
    :type write_to_pcap_in: bool
    :param write_to_pcap_in: write traffic to pcap file
    """
    api_sniffer.write_to_pcap = write_to_pcap_in

def get_writing_to_pcap():
    return api_sniffer.write_to_pcap

def start_sniffing():
    """
    Starts sniffing and sets the abort variable api_sniffer.isListening to True
    """
    api_sniffer.isListening = True
    if api_sniffer.isListening:
        api_sniffer.start_sniffing_traffic()

def stop_sniffing():
    """
    Stopps sniffing and sets the abort variable api_sniffer.isListening to False.
    After next packet is sniffed, and abort variable gets checkt, sniffing stopps.
    """
    api_sniffer.isListening = False

def get_isListening():
    """
    Returns sniffing abort variable to check whether or not is sniffing now.
    :returns: isListening
    :rtype: bool
    """
    return api_sniffer.isListening


# INIT
api_info = info_class()
api_db = db_class()
api_dhcp = dhcp_class()
api_sniffer = sniffer_class()
api_sniffer.db_path =api_db.db_path

init_hw()

# WHATNOT