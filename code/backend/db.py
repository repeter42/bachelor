import sqlite3 as sql
from datetime import datetime as dt

class db_class():

    def __init__(self):
        self.db_path= f"/root/ba/traffic_{dt.utcnow}.db"
        self.init_db()
        
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

    def get_packets(self, query):
        """
        Fetches packets from database.

        :param query: 
        :query type: list
        :returns: list of packets
        :type: [tuple]
        """

        print("WICHTIG MUSS NOCH GEMACHT WERDEN")
