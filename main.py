import os
import time
import csv
import json
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

CACHE_FILE = "cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_cache(cache_data):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, indent=4)

def is_valid_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not ip.is_private and not ip.is_loopback
    except ValueError:
        return False

def check_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            print(f" [!] AbuseIPDB HTTP {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f" [!] AbuseIPDB Hatası: {e}")
        return None

def check_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        else:
            print(f" [!] VirusTotal HTTP {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f" [!] VirusTotal Hatası: {e}")
        return None

def process_ip_list(input_file="ips.txt", output_csv="triage_report.csv"):
    if not os.path.exists(input_file):
        print(f"[-] '{input_file}' dosyası bulunamadı!")
        return

    with open(input_file, "r") as f:
        raw_ips = [line.strip() for line in f if line.strip()]

    unique_ips = list(set(raw_ips))
    print(f"[*] Toplam satır sayısı: {len(raw_ips)} -> Benzersiz IP sayısı: {len(unique_ips)}")

    cache = load_cache()

    fieldnames = [
        "ip", "country", "isp", "abuse_score", 
        "vt_malicious", "vt_suspicious", "decision", "source", "timestamp"
    ]

    results = []

    for idx, ip in enumerate(unique_ips, 1):
        if not is_valid_ip(ip):
            print(f"[{idx}/{len(unique_ips)}] {ip} -> Geçersiz veya Özel IP (Private/RFC1918). Atlanıyor.")
            continue

        if ip in cache:
            print(f"[{idx}/{len(unique_ips)}] {ip} -> [CACHE HIT] Diskten okundu, kota harcanmadı.")
            data = cache[ip]
            data["source"] = "CACHE"
            results.append(data)
            continue

        print(f"[{idx}/{len(unique_ips)}] {ip} -> [API SORGUSU] Canlı veri çekiliyor...")
        abuse_data = check_abuseipdb(ip)
        vt_stats = check_virustotal(ip)

        abuse_score = abuse_data.get("abuseConfidenceScore", 0) if abuse_data else 0
        country = abuse_data.get("countryCode", "Unknown") if abuse_data else "Unknown"
        isp = abuse_data.get("isp", "Unknown") if abuse_data else "Unknown"

        vt_malicious = vt_stats.get("malicious", 0) if vt_stats else 0
        vt_suspicious = vt_stats.get("suspicious", 0) if vt_stats else 0

        if abuse_score >= 50 or vt_malicious >= 3:
            decision = "CRITICAL"
        elif abuse_score > 0 or vt_malicious > 0 or vt_suspicious > 0:
            decision = "SUSPICIOUS"
        else:
            decision = "CLEAN"

        ip_record = {
            "ip": ip,
            "country": country,
            "isp": isp,
            "abuse_score": abuse_score,
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
            "decision": decision,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        cache[ip] = ip_record
        save_cache(cache)

        ip_record_for_csv = dict(ip_record)
        ip_record_for_csv["source"] = "API"
        results.append(ip_record_for_csv)

        print(f"    └─ Karar: {decision} | Abuse: %{abuse_score} | VT: {vt_malicious} motor")

        if idx < len(unique_ips):
            time.sleep(15)

    with open(output_csv, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Triyaj tamamlandı! Rapor: {output_csv}")

if __name__ == "__main__":
    process_ip_list()