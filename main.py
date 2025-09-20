import os
import time
import threading
import signal
import sys
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from scapy.config import conf

conf.debug_dissector = 2
# Interface
iface = "wlan0"

# Track discovered APs and clients
seen_aps = {}
seen_clients = {}
client_associations = {}

# --- Helpers ---
def run_cmd(cmd):
    """Run a shell command and suppress output."""
    os.system(cmd + " >/dev/null 2>&1")

def set_monitor_mode():
    """Put interface into monitor mode."""
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw dev {iface} set type monitor")
    run_cmd(f"ip link set {iface} up")

def restore_managed_mode():
    """Restore interface to managed mode (normal Wi-Fi)."""
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw dev {iface} set type managed")
    run_cmd(f"ip link set {iface} up")

def set_channel(ch):
    """Set Wi-Fi channel."""
    try:
        run_cmd(f"iw dev {iface} set channel {ch}")
       # print(f"🔄 Switched to channel {ch}")
        time.sleep(0.5)  # Kurze Pause nach Channel-Wechsel
    except Exception as e:
        print(f"Error setting channel {ch}: {e}")

def channel_hopper():
    """Background thread: hop through channels."""
    channels = [1, 6, 11]
    while True:
        for ch in channels:
            try:
                set_channel(ch)
                time.sleep(5.0)  # Länger warten - war 2.0
            except Exception as e:
                print(f"Channel hop error: {e}")
                time.sleep(1.0)


def handle_beacon_frame(pkt):
    """Handle Access Point beacon frames"""
    ssid = pkt.info.decode(errors="ignore")
    bssid = pkt.addr2

    if bssid not in seen_aps:
        seen_aps[bssid] = ssid or '<hidden>'
        # print(f"[AP] SSID: {ssid or '<hidden>'} | BSSID: {bssid}")


def handle_probe_request(pkt):
    """Handle client probe requests"""
    client = pkt.addr2
    ssid = pkt.info.decode(errors="ignore")

    if client not in seen_clients:
        seen_clients[client] = {
            'connected_to': None,
            'ssid': None,
            'probes': []
        }

    # Track what SSIDs this client is probing for
    if ssid and ssid not in seen_clients[client]['probes']:
        seen_clients[client]['probes'].append(ssid)


def handle_association_request(pkt):
    """Handle client association requests"""
    client = pkt.addr2
    ap_bssid = pkt.addr1

    if client not in seen_clients:
        seen_clients[client] = {'connected_to': None, 'ssid': None, 'probes': []}

    seen_clients[client]['connected_to'] = ap_bssid
    seen_clients[client]['ssid'] = seen_aps.get(ap_bssid, 'Unknown')
    print(f"[ASSOC] Client {client} associating with {ap_bssid}")


def handle_data_frame(pkt):
    """Handle data frames to track active connections"""
    src = pkt.addr2
    dst = pkt.addr1
    bssid = pkt.addr3

    # Client to AP traffic
    if src in seen_clients and dst in seen_aps:
        seen_clients[src]['connected_to'] = dst
        seen_clients[src]['ssid'] = seen_aps.get(dst, 'Unknown')

    # AP to Client traffic
    elif src in seen_aps and dst in seen_clients:
        seen_clients[dst]['connected_to'] = src
        seen_clients[dst]['ssid'] = seen_aps.get(src, 'Unknown')


def packet_handler(pkt):
    """Main packet processing dispatcher"""
    if not pkt.haslayer(Dot11):
        return

    # Management frames
    if pkt.type == 0:
        if pkt.subtype == 8:  # Beacon frames
            handle_beacon_frame(pkt)
        elif pkt.subtype == 4:  # Probe requests
            handle_probe_request(pkt)
        elif pkt.subtype == 0:  # Association requests
            handle_association_request(pkt)

    # Data frames
    elif pkt.type == 2:
        handle_data_frame(pkt)
def start_sniffing():
    """Sniffing with automatic restart on socket errors"""
    while True:
        try:
            print("🔍 Starting packet capture...")
            sniff(iface=iface, prn=packet_handler, store=0, timeout=30)
        except Exception as e:
            print(f"⚠️  Socket error: {e}")
            print("🔄 Restarting in 3 seconds...")
            time.sleep(3)
            # Reinitialize interface
            restore_managed_mode()
            time.sleep(1)
            set_monitor_mode()
            time.sleep(2)


def print_seen():
    """Print currently seen APs and clients."""
    print("\n" + "=" * 70)
    print("📡 DISCOVERED ACCESS POINTS")
    print("=" * 70)

    for bssid, ssid in seen_aps.items():
        # Count connected clients
        connected_count = sum(1 for client_info in seen_clients.values()
                              if client_info['connected_to'] == bssid)
        print(f"SSID: {ssid:<20} | BSSID: {bssid} | Clients: {connected_count}")

    print("\n" + "=" * 70)
    print("👥 DISCOVERED CLIENTS")
    print("=" * 70)

    for client_mac, client_info in seen_clients.items():
        if client_info['connected_to']:
            status = f"Connected to: {client_info['ssid']} ({client_info['connected_to']})"
        elif client_info['probes']:
            status = f"Probing for: {', '.join(client_info['probes'][:3])}"  # Show first 3 probes
        else:
            status = "Status unknown"

        print(f"Client: {client_mac} | {status}")

    print(f"\n📊 Total APs: {len(seen_aps)}")
    print(f"📊 Total Clients: {len(seen_clients)}")
    print("=" * 70)

def periodic_summary():
    """Print summary every 30 seconds"""
    while True:
        time.sleep(5)
        print_seen()

# In main, replace the lambda thread with:
threading.Thread(target=periodic_summary, daemon=True).start()
# --- Graceful shutdown ---
def handle_exit(sig, frame):
    print("\n⚠️  Restoring interface and exiting...")
    restore_managed_mode()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# --- Main ---
if __name__ == "__main__":
    print("🔧 Setting interface to monitor mode...")
    set_monitor_mode()

    print("🚀 Starting channel hopper...")
    threading.Thread(target=channel_hopper, daemon=True).start()

    threading.Thread(target=periodic_summary, daemon=True).start()

    print("🔍 Sniffing across channels (Ctrl+C to stop)...\n")
    start_sniffing()
