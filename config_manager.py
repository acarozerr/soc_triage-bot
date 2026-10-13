import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".soar_triage"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    # Splunk
    "SPLUNK_HOST": "",
    "SPLUNK_PORT": "8089",
    "SPLUNK_USERNAME": "admin",
    "SPLUNK_PASSWORD": "",
    "SPLUNK_INDEX": "",
    # Wazuh
    "WAZUH_HOST": "",
    "WAZUH_PORT": "55000",
    "WAZUH_USERNAME": "wazuh-wui",
    "WAZUH_PASSWORD": "",
    "WAZUH_MIN_LEVEL": "3",
    # Threat Intel
    "ABUSEIPDB_API_KEY": "",
    "VIRUSTOTAL_API_KEY": ""
}

def load_config():
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    if not CONFIG_FILE.exists():
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                data.setdefault(k, v)
            return data
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg_dict):
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg_dict, f, indent=4)

def is_configured():
    cfg = load_config()
    # Splunk VEYA Wazuh'tan en az birinin sunucu ve şifre bilgisi girilmiş olmalı
    splunk_ready = bool(cfg.get("SPLUNK_HOST") and cfg.get("SPLUNK_PASSWORD"))
    wazuh_ready = bool(cfg.get("WAZUH_HOST") and cfg.get("WAZUH_PASSWORD"))
    return splunk_ready or wazuh_ready