from scapy.layers.dot11 import Dot11


class PacketHandlers:
    def __init__(self, seen_aps, seen_clients):
        self.seen_aps = seen_aps
        self.seen_clients = seen_clients

    def handle_beacon_frame(self, pkt):
        """Handle Access Point beacon frames"""
        ssid = pkt.info.decode(errors="ignore")
        bssid = pkt.addr2

        if bssid not in self.seen_aps:
            self.seen_aps[bssid] = ssid or '<hidden>'
            # print(f"[AP] SSID: {ssid or '<hidden>'} | BSSID: {bssid}")

    def handle_probe_request(self, pkt):
        """Handle client probe requests"""
        client = pkt.addr2
        ssid = pkt.info.decode(errors="ignore")

        if client not in self.seen_clients:
            self.seen_clients[client] = {
                'connected_to': None,
                'ssid': None,
                'probes': []
            }

        # Track what SSIDs this client is probing for
        if ssid and ssid not in self.seen_clients[client]['probes']:
            self.seen_clients[client]['probes'].append(ssid)

    def handle_association_request(self, pkt):
        """Handle client association requests"""
        client = pkt.addr2
        ap_bssid = pkt.addr1

        if client not in self.seen_clients:
            self.seen_clients[client] = {'connected_to': None, 'ssid': None, 'probes': []}

        self.seen_clients[client]['connected_to'] = ap_bssid
        self.seen_clients[client]['ssid'] = self.seen_aps.get(ap_bssid, 'Unknown')
        print(f"[ASSOC] Client {client} associating with {ap_bssid}")

    def handle_data_frame(self, pkt):
        """Handle data frames to track active connections"""
        src = pkt.addr2
        dst = pkt.addr1
        bssid = pkt.addr3

        # Client to AP traffic
        if src in self.seen_clients and dst in self.seen_aps:
            self.seen_clients[src]['connected_to'] = dst
            self.seen_clients[src]['ssid'] = self.seen_aps.get(dst, 'Unknown')

        # AP to Client traffic
        elif src in self.seen_aps and dst in self.seen_clients:
            self.seen_clients[dst]['connected_to'] = src
            self.seen_clients[dst]['ssid'] = self.seen_aps.get(src, 'Unknown')

    def packet_handler(self, pkt):
        """Main packet processing dispatcher"""
        if not pkt.haslayer(Dot11):
            return

        # Management frames
        if pkt.type == 0:
            if pkt.subtype == 8:  # Beacon frames
                self.handle_beacon_frame(pkt)
            elif pkt.subtype == 4:  # Probe requests
                self.handle_probe_request(pkt)
            elif pkt.subtype == 0:  # Association requests
                self.handle_association_request(pkt)

        # Data frames
        elif pkt.type == 2:
            self.handle_data_frame(pkt)
