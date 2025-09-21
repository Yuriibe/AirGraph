# WiFi Network Scanner

A passive WiFi monitoring tool that discovers access points and tracks client associations in real-time, featuring a web-based interface for visualization.

## Features

- **Passive monitoring** - Undetectable scanning using monitor mode
- **Real-time discovery** - Detects access points and connected clients
- **Client tracking** - Maps client associations and probe requests
- **Vendor identification** - MAC address vendor lookup
- **Web interface** - Live dashboard at http://localhost:5000
- **Channel hopping** - Scans across multiple WiFi channels automatically

## Requirements

- Linux system with wireless adapter supporting monitor mode
- Python 3.7+
- Root privileges for monitor mode operations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Yuriibe/AirGraph.git
cd AirGraph
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure your wireless adapter supports monitor mode:
```bash
sudo airmon-ng check
```

## Configuration

Edit `config/settings.py` to customize:
- `INTERFACE` - Your wireless interface name
- `CHANNELS` - WiFi channels to monitor 
- `CHANNEL_DWELL_TIME` - Time spent on each channel
- `SUMMARY_INTERVAL` - Console output frequency
- `VENDOR_DB_PATH` - Path to MAC vendor database

## Usage

Run the scanner with root privileges:
```bash
sudo python main.py
```

The scanner will:
1. Set your wireless interface to monitor mode
2. Start channel hopping across configured channels
3. Begin packet capture and analysis
4. Launch web interface on port 5000
5. Display periodic summaries in console

Access the web dashboard at: **http://localhost:5000**

## Project Structure

```
wifiscanner/
├── main.py                 # Entry point
├── config/
│   └── settings.py         # Configuration
├── core/
│   ├── network_scanner.py  # Channel hopping & packet capture
│   └── packet_handler.py   # 802.11 frame processing
├── display/
│   └── formatter.py        # Console output formatting
├── helper/
│   ├── interface_manager.py # Monitor mode management
│   └── vendor_manager.py    # MAC vendor lookups
└── web/
    ├── server.py           # Flask web server
    └── templates/
        └── index.html      # Web dashboard
```

## Example Output
```
======================================================================
📡 DISCOVERED ACCESS POINTS
======================================================================
SSID: HomeNetwork          | BSSID: xx:xx:xx:xx:xx:01 | Clients: 2 | Vendor: Cisco Systems Inc
SSID: GuestWiFi            | BSSID: xx:xx:xx:xx:xx:02 | Clients: 0 | Vendor: Netgear Inc.
SSID: OfficeNet            | BSSID: xx:xx:xx:xx:xx:03 | Clients: 1 | Vendor: TP-LINK TECHNOLOGIES
======================================================================
👥 DISCOVERED CLIENTS
======================================================================
Client: xx:xx:xx:xx:xx:10 | Connected to: HomeNetwork (xx:xx:xx:xx:xx:01) | Vendor: Apple Inc.
Client: xx:xx:xx:xx:xx:11 | Probing for: HomeNetwork | Vendor: Samsung Electronics
Client: xx:xx:xx:xx:xx:12 | Status unknown | Vendor: Intel Corporate
```
## Legal Notice

This tool is designed for network security assessment and educational purposes. Only use on networks you own or have explicit permission to test. Unauthorized network monitoring may violate local laws.

## Detected Information

- **Access Points**: SSID, BSSID, vendor, connected client count
- **Clients**: MAC address, connection status, probe requests, vendor
- **Associations**: Which clients are connected to which access points

## Stopping the Scanner

Press `Ctrl+C` to stop. The interface manager will automatically restore your wireless adapter to its original state.

## Troubleshooting

**Interface errors**: Ensure no other tools are using your wireless adapter
**Permission denied**: Run with `sudo`
**No packets captured**: Verify your adapter supports monitor mode
**Web interface shows no data**: Check console for any error messages
