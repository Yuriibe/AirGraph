import time
import threading
import json
import os

from scapy.all import sniff
from scapy.config import conf

from helper.interface_manager import InterfaceManager
from config.settings import Config
from display.formatter import NetworkFormatter, DataStore
from handler.packet_handler import PacketHandlers

conf.debug_dissector = 2

# Track discovered APs and clients
seen_aps = {}
seen_clients = {}
client_associations = {}
vendor_map = None


def channel_hopper(manager):
    """Background thread: hop through channels."""
    channels = Config.CHANNELS
    while True:
        for ch in channels:
            try:
                manager.set_channel(ch)
                time.sleep(Config.CHANNEL_DWELL_TIME)
            except Exception as e:
                print(f"Channel hop error: {e}")
                time.sleep(1.0)


def start_sniffing(manager, packet_handlers):
    """Single sniff session with error handling"""
    try:
        print("🔍 Starting packet capture...")
        sniff(iface=manager.iface, prn=packet_handlers.packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Capture interrupted by user")
    except OSError as e:
        print(f"⚠️ Socket error: {e}")
        print("🔄 Restarting in 3 seconds...")
        time.sleep(3)
        start_sniffing(manager, packet_handlers)


def load_vendor_map(path):
    if not os.path.exists(path):
        print(f"Vendor DB file not found: {path}")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vm = {}
    for entry in data:
        prefix = entry.get("macPrefix", "").replace(":", "").upper()
        vendor = entry.get("vendorName", "").strip()
        if prefix and vendor:
            vm[prefix] = vendor
    return vm


def find_vendor_by_mac(mac):
    prefix = mac.upper().replace(":", "")[:6]
    return vendor_map.get(prefix, "Unknown Vendor")


def periodic_summary(formatter):
    """Print summary every interval"""
    while True:
        time.sleep(Config.SUMMARY_INTERVAL)
        formatter.print_full_summary()


# --- Main ---
if __name__ == "__main__":
    vendor_map = load_vendor_map(Config.VENDOR_DB_PATH)

    # Create packet handlers instance
    packet_handlers = PacketHandlers(seen_aps, seen_clients)

    with InterfaceManager(Config.INTERFACE) as iface_manager:
        print("🚀 Starting channel hopper...")
        threading.Thread(
            target=channel_hopper,
            args=(iface_manager,),
            daemon=True,
        ).start()

        threading.Thread(
            target=periodic_summary,
            args=(NetworkFormatter(
                DataStore(seen_aps, seen_clients),
                find_vendor_by_mac,
            ),),
            daemon=True,
        ).start()

        print("🔍 Sniffing across channels (Ctrl+C to stop)...\n")
        start_sniffing(iface_manager, packet_handlers)
