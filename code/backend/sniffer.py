from scapy.all import *
import sqlite3 as sql
from datetime import datetime as dt

from backend.scan import scan_settings
from love_gpt import EthPortTestApp

def packet_handler(pkt):
    """
    This function triggers when a new packet is detected by the scapys sniff function. It writes the packet to a pcap file and into the database
    """
    wrpcap("traffic.pcap", pkt, append=True)     # appends sniffed packets to pcap file

    pkt_values = [None] * 10         # later to be converted into a tuple to write into database ... filled with None's so when intendet value can not be parsed, None will be written into database
    # following should always be true as packets are sent as ethernet frame and therefore returned as ethernet frame ... but just in case
    if pkt.haslayer("Ether"):
        pkt_values[0] = pkt["Ether"].src
        pkt_values[1] = pkt["Ether"].dst
        pkt_values[2] = pkt["Ether"].type       # most times it is IPv4 but sometimes it is a low level protocol packet

    if pkt.haslayer("IP"):
        pkt_values[3] = pkt["IP"].src
        pkt_values[4] = pkt["IP"].dst
        proto = "Unknown"           # you could also set the protocol number here, but when sorting 
        try:
            proto_field = pkt["IP"].get_field("proto")  # gets the field proto from IP
            proto = proto_field.i2s[pkt["IP"].proto]          # gets the actual protocal name instead of the protocol number
        except:
            print("Unknonwn Protocol: protocol Number could not be matched to protocol name")
        pkt_values[5] = proto

    if pkt.haslayer("TCP"):
        pkt_values[6] = pkt["TCP"].sport
        pkt_values[7] = pkt["TCP"].dport
    
    if pkt.haslayer("UDP"):
        pkt_values[6] = pkt["UDP"].sport
        pkt_values[7] = pkt["UDP"].dport

    if pkt.haslayer("Raw"):
        pkt_values[9] = pkt["Raw"].load

    pkt_values[8] = dt.now()
    pkt_values_tuple = tuple(pkt_values)

    connection = sql.connect(db_path)
    cursor = connection.cursor()
    insert_cmd = """ INSERT INTO packets (mac_src, mac_dst, eth_type, ip_src, ip_dst, transport_proto, src_port, dst_port, timestamp, raw_data)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?); """
    cursor.execute(insert_cmd, pkt_values_tuple)
    connection.commit()
    connection.close()

    EthPortTestApp.add_row(packet)


def stop_sniffing(x):
    if scan_settings.get_isListening():
        return False
    else:
        return True


def sniff_traffic():
    # while scan_settings.get_isListening():
    #    print(scan_settings.get_isListening())
    iface_name = scan_settings.get_nicInfo()[0]
    sniff(prn=packet_handler, stop_filter=stop_sniffing, iface=iface_name)       # it is important to not actually call the function packet_handler() instead only name it to be called on packets arival ... otherwise scapy does not turn over the packet previously sniffed and the function is missing the required input


def init_db():
    connection = sql.connect(db_path)       # connection to the database ... if not already exitst it will be created
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


db_path= "/home/tester/ba/traffic.db"
init_db()
sniff_traffic()
# print(dt.utcfromtimestamp(2389070846))