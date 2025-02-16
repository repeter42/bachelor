from flask import Flask, render_template
from backend.scan import scan_settings

app = Flask(__name__)

def get_packets(query):
    packets = [
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        {"id": 1, "proto": "TCP", "src_mac": "00:1A:2B:3C:4D:5E", "dst_mac": "00:5E:4D:3C:2B:1A", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
        {"id": 2, "proto": "UDP", "src_mac": "11:22:33:44:55:66", "dst_mac": "66:55:44:33:22:11", "src_ip": "192.168.1.3", "dst_ip": "192.168.1.4"},
        # Add more packets as needed
    ]
    return packets



@app.route("/")
def hello_world():
    query = "test"
    packets = get_packets(query)
    return render_template("index.html", packets=packets)


app.run(host="127.0.0.1", port=9001, debug=True)