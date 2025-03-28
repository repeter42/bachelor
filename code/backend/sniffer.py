from scapy.all import *
import sqlite3 as sql
import datetime as dt
# import multiprocessing

from info import my_info as api_info
# from db import my_db as api_db

class sniffer_class():

    def __init__(self):
        self.isListening = None     # going to be multiporcess managed value
        self.newPacket = None   
        self.db_path = None
        self.timeout = 2
        self.write_to_pcap = True
        subprocess.run("mkdir /var/opt/connectest", shell=True)
        self.pcap_path= f"/var/opt/connectest/traffic_{dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%S')}.pcap"
        self.db_path = "/var/opt/connectest/traffic.db"


    def packet_handler(self, pkt_in):
        """
        This function triggers when a new packet is detected by the scapys sniff function. It writes the packet to a pcap file and into the database.
        """
        if self.write_to_pcap:
            wrpcap(self.pcap_path, pkt_in, append=True)     # appends sniffed packets to pcap file
        
        
        pkt_values = [None] * 11         # later to be converted into a tuple to write into database ... filled with None's so when intendet value can not be parsed, None will be written into database

        # following should always be true as packets are sent as ethernet frame and therefore returned as ethernet frame ... but just in case
        if pkt_in.haslayer("Ether"):
            pkt_values[0] = pkt_in["Ether"].src
            pkt_values[1] = pkt_in["Ether"].dst
            pkt_values[2] = pkt_in["Ether"].type       # most times it is IPv4 but sometimes it is a low level protocol packet

        if pkt_in.haslayer("IP"):
            pkt_values[3] = pkt_in["IP"].src
            pkt_values[4] = pkt_in["IP"].dst
            proto = "Unknown"           # you could also set the protocol number here, but when sorting 
            try:
                proto_field = pkt_in["IP"].get_field("proto")      # gets the field proto from IP
                proto = proto_field.i2s[pkt_in["IP"].proto]        # gets the actual protocal name instead of the protocol number
            except:
                print("Unknonwn Protocol: protocol Number could not be matched to protocol name")
            pkt_values[5] = proto

        if pkt_in.haslayer("TCP"):
            pkt_values[6] = pkt_in["TCP"].sport
            pkt_values[7] = pkt_in["TCP"].dport
        
        if pkt_in.haslayer("UDP"):
            pkt_values[6] = pkt_in["UDP"].sport
            pkt_values[7] = pkt_in["UDP"].dport

        if pkt_in.haslayer("Raw"):
            pkt_values[9] = pkt_in["Raw"].load

        pkt_values[8] = dt.datetime.now(dt.UTC)
        pkt_values[10] = pkt_in.show(dump=True)
        pkt_values_tuple = tuple(pkt_values)

        self.newPacket = True

        # This could (maybe even should) be in the database compnent but simplicity
        connection = sql.connect(self.db_path)
        cursor = connection.cursor()
        insert_cmd = """ INSERT INTO packets (mac_src, mac_dst, eth_type, ip_src, ip_dst, transport_proto, src_port, dst_port, timestamp, raw_data, pkt_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?); """
        cursor.execute(insert_cmd, pkt_values_tuple)
        connection.commit()
        connection.close()

    def stop_sniffing_check(self, x):
        stop_sniffing = None    # values could be returned in if decision -> but this proides better overview especially for debugging
        if self.isListening.value:
            stop_sniffing = False
        else:
            stop_sniffing = True
        return stop_sniffing

    def start_sniffing_traffic(self):
        """
        Starts sniffing process ... in theory at least
        """
        iface_name = api_info.get_nicInfo()[0]
        # self.isListening.value = True   # should be set by api right bevor calling this function
        sniff(prn=self.packet_handler, stop_filter=self.stop_sniffing_check, iface=iface_name) # ,count=1)
        # it is important to not actually call the function packet_handler() instead only name it to be called on packets arival ... 
        # otherwise scapy does not turn over the packet previously sniffed and the function is missing the required input

