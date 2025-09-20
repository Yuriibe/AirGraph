import time
from scapy.all import sniff


class NetworkScanner:
    def __init__(self, interface_manager, config):
        self.interface_manager = interface_manager
        self.config = config

    def channel_hopper(self):
        """Background thread: hop through channels."""
        channels = self.config.CHANNELS
        while True:
            for ch in channels:
                try:
                    self.interface_manager.set_channel(ch)
                    time.sleep(self.config.CHANNEL_DWELL_TIME)
                except Exception as e:
                    print(f"Channel hop error: {e}")
                    time.sleep(1.0)

    def start_sniffing(self, packet_handlers):
        """Single sniff session with error handling"""
        try:
            print("🔍 Starting packet capture...")
            sniff(iface=self.interface_manager.iface, prn=packet_handlers.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n🛑 Capture interrupted by user")
        except OSError as e:
            print(f"⚠️ Socket error: {e}")
            print("🔄 Restarting in 3 seconds...")
            time.sleep(3)
            self.start_sniffing(packet_handlers)
