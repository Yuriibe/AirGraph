import threading

from scapy.config import conf

from config.settings import Config
from core.network_scanner import NetworkScanner
from core.packet_handler import PacketHandlers
from display.formatter import NetworkFormatter, DataStore
from helper.interface_manager import InterfaceManager
from helper.vendor_manager import VendorManager

conf.debug_dissector = 2

# Track discovered APs and clients
seen_aps = {}
seen_clients = {}

# --- Main ---
if __name__ == "__main__":
    vendor_manager = VendorManager(Config.VENDOR_DB_PATH)
    packet_handlers = PacketHandlers(seen_aps, seen_clients)

    with InterfaceManager(Config.INTERFACE) as iface_manager:
        scanner = NetworkScanner(iface_manager, Config)
        formatter = NetworkFormatter(
            DataStore(seen_aps, seen_clients),
            vendor_manager.find_vendor_by_mac
        )

        print("🚀 Starting channel hopper...")
        threading.Thread(target=scanner.channel_hopper, daemon=True).start()
        threading.Thread(target=formatter.periodic_summary, daemon=True).start()

        print("🔍 Sniffing across channels (Ctrl+C to stop)...\n")
        scanner.start_sniffing(packet_handlers)
