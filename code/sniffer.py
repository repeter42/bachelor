import scapy
from scapy.all import *

from scan import scan_settings

def packet_handler(pkt):
    """
    This function triggers when a new packet is detected by the scapys sniff function.
    """
    wrpcap("traffic.pcap", pkt, append=True)     # appends sniffed packets to pcap file
    


def stop_sniffing(x):
    if scan_settings.get_isListening():
        return False
    else:
        return True



def sniff_traffic():
    # while scan_settings.get_isListening():
    #    print(scan_settings.get_isListening())
    sniff(prn=packet_handler, stop_filter=stop_sniffing)       # it is important to not actually call the function packet_handler() instead only name it to be called on packets arival ... otherwise scapy does not turn over the packet previously sniffed and the function is missing the required input

sniff_traffic()
