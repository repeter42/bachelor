from scapy.all import *
import sqlite3 as sql
from datetime import datetime as dt

from backend.hwinfo import my_hw_info
from frontend.kivy_ui import EthPortTestApp
from frontend.kivy_ui import my_eth_tester

class sniffer():
    def __init__(self):
        self.isListening = True
        self.timeout = 2
        self.packet_id = 0
        self.write_to_pcap = False
        self.db_path= f"/home/tester/ba/traffic_{dt.utcnow}.db"
        self.init_db()

    def set_isListening(self, isListening_in):
        self.isListening = isListening_in
        if self.isListening:
            self.sniff_traffic()
    
    def get_isListening(self):
        return self.isListening

    def packet_handler(self, pkt):
        """
        This function triggers when a new packet is detected by the scapys sniff function. It writes the packet to a pcap file and into the database
        """
        if self.write_to_pcap:
            wrpcap("traffic.pcap", pkt, append=True)     # appends sniffed packets to pcap file

        pkt_values = [None] * 11         # later to be converted into a tuple to write into database ... filled with None's so when intendet value can not be parsed, None will be written into database
        # packet id needs to be set manually so that the id can be turned over to the ui ... otherwise the database could do that implicitly
        pkt_values[0] = self.packet_id
        self.packet_id += 1
        # following should always be true as packets are sent as ethernet frame and therefore returned as ethernet frame ... but just in case
        if pkt.haslayer("Ether"):
            pkt_values[1] = pkt["Ether"].src
            pkt_values[2] = pkt["Ether"].dst
            pkt_values[3] = pkt["Ether"].type       # most times it is IPv4 but sometimes it is a low level protocol packet

        if pkt.haslayer("IP"):
            pkt_values[4] = pkt["IP"].src
            pkt_values[5] = pkt["IP"].dst
            proto = "Unknown"           # you could also set the protocol number here, but when sorting 
            try:
                proto_field = pkt["IP"].get_field("proto")      # gets the field proto from IP
                proto = proto_field.i2s[pkt["IP"].proto]        # gets the actual protocal name instead of the protocol number
            except:
                print("Unknonwn Protocol: protocol Number could not be matched to protocol name")
            pkt_values[6] = proto

        if pkt.haslayer("TCP"):
            pkt_values[7] = pkt["TCP"].sport
            pkt_values[8] = pkt["TCP"].dport
        
        if pkt.haslayer("UDP"):
            pkt_values[7] = pkt["UDP"].sport
            pkt_values[8] = pkt["UDP"].dport

        if pkt.haslayer("Raw"):
            pkt_values[10] = pkt["Raw"].load

        pkt_values[9] = dt.now()
        pkt_values_tuple = tuple(pkt_values)

        connection = sql.connect(self.db_path)
        cursor = connection.cursor()
        insert_cmd = """ INSERT INTO packets (packet_id, mac_src, mac_dst, eth_type, ip_src, ip_dst, transport_proto, src_port, dst_port, timestamp, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?); """
        cursor.execute(insert_cmd, pkt_values_tuple)
        connection.commit()
        connection.close()

        my_eth_tester.add_packet(packet=pkt_values_tuple)


    def stop_sniffing(x):
        if my_hw_info.get_isListening():
            return False
        else:
            return True


    def sniff_traffic(self):
        # while scan_settings.get_isListening():
        #    print(scan_settings.get_isListening())
        iface_name = my_hw_info.get_nicInfo()[0]
        sniff(prn=self.packet_handler, stop_filter=self.stop_sniffing, iface=iface_name)       # it is important to not actually call the function packet_handler() instead only name it to be called on packets arival ... otherwise scapy does not turn over the packet previously sniffed and the function is missing the required input


    def init_db(self):
        connection = sql.connect(self.db_path)       # connection to the database ... if not already exitst it will be created
        cursor = connection.cursor()            # is used to interact with database

        # enable wal mode (write ahead logging) --> enables simultanious read and write ... as far as i know
        cursor.execute("PRAGMA journal_mode = WAL;")  

        # the following command creates the table for the database which is to be populated later
        create_table = """ CREATE TABLE IF NOT EXISTS packets(
        packet_id INTEGER PRIMARY KEY,
        mac_src TEXT NOT NULL, 
        mac_dst TEXT NOT NULL,
        eth_type TEXT NOT NULL,
        ip_src TEXT,
        ip_dst TEXT,
        transport_proto TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        raw_data BLOB
        ); """
        cursor.execute(create_table)
        connection.commit()
        connection.close()

