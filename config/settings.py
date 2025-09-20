class Config:
    INTERFACE = "wlan0"
    # https://maclookup.app/downloads/json-database
    VENDOR_DB_PATH = "mac-vendors-export.json"
    CHANNELS = [1, 6, 11]
    CHANNEL_DWELL_TIME = 5.0
    SUMMARY_INTERVAL = 5
