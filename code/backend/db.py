import sqlite3 as sql
import datetime as dt
import subprocess   # from scapy.all import *

class db_class():

    def __init__(self):
        # db path always the same, as db is only temporary data save -> real save in pcap file
        subprocess.run("mkdir /var/opt/connectest", shell=True)
        self.db_path = "/var/opt/connectest/traffic.db"
        self.init_db()

    def init_db(self):
        self.drop_table()
        connection = sql.connect(self.db_path)      # connection to the database ... if not already exitst it will be created
        cursor = connection.cursor()                # is used to interact with database

        # enable wal mode (write ahead logging) --> enables simultanious read and write ... as far as i know
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA read_uncommitted=1;")

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
        raw_data BLOB,
        pkt_details
        ); """
        cursor.execute(create_table)
        connection.commit()
        connection.close()

    def get_packets(self, query = "*"):
        """
        Fetches packets from database.

        :param query: comma seperated values to query db
        :query type: string
        :returns: packets queried from databae
        :type: [tuple]
        """
        # checking if query is a string ... further security checks could be implemented here
        if not isinstance(query, str):
            return False
        
        packets = None
        connection = sql.connect(self.db_path)
        cursor = connection.cursor()
        select_cmd = f"SELECT {query} FROM packets;"
        cursor.execute(select_cmd)
        connection.commit()
        connection.close()

        return packets

    # def write_packet(self, pkt_in): 
        """
        Moved to sniffer, as only write acces happens in sniffer -> simpler
        """

    def drop_table(self):
        """
        After sniffing is done and user decides to delete sniffed packets -> table gets dropped.
        """
        connection = sql.connect(self.db_path)
        cursor = connection.cursor()
        drop_cmd = "DROP TABLE IF EXISTS packets;"
        cursor.execute(drop_cmd)
        connection.commit()
        connection.close()

my_db = db_class()