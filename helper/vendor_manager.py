import json
import os


class VendorManager:
    def __init__(self, vendor_db_path):
        self.vendor_map = self.load_vendor_map(vendor_db_path)

    def load_vendor_map(self, path):
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

    def find_vendor_by_mac(self, mac):
        prefix = mac.upper().replace(":", "")[:6]
        return self.vendor_map.get(prefix, "Unknown Vendor")  # Changed vendor_map to self.vendor_map
