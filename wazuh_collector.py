import os
import json
import base64
from pathlib import Path
import requests
from dotenv import load_dotenv

# SSL sertifika uyarılarını kapatmak için (Wazuh genelde self-signed cert kullanır)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent

def get_wazuh_token(host, port, username, password):
    """Wazuh REST API üzerinden JWT oturum token'ı alır."""
    url = f"https://{host}:{port}/security/user/authenticate"
    auth_str = f"{username}:{password}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/json"
    }

    response = requests.post(url, headers=headers, verify=False, timeout=10)
    if response.status_code == 200:
        data = response.json()
        return data.get("data", {}).get("token")
    else:
        raise Exception(f"Kimlik doğrulama başarısız ({response.status_code}): {response.text}")

def test_wazuh_connection(host, port, username, password):
    """Wazuh API bağlantısını ve kimlik bilgilerini canlı test eder."""
    try:
        token = get_wazuh_token(host, port, username, password)
        if not token:
            return False, "Token alınamadı."
        
        # Sürüm ve yönetici bilgisini sorgula
        headers = {"Authorization": f"Bearer {token}"}
        url = f"https://{host}:{port}/manager/info"
        res = requests.get(url, headers=headers, verify=False, timeout=10)
        
        if res.status_code == 200:
            info = res.json().get("data", {}).get("affected_items", [{}])[0]
            version = info.get("version", "Bilinmiyor")
            return True, f"Bağlantı Başarılı! (Wazuh v{version})"
        return True, "Bağlantı başarılı fakat yönetici bilgisi okunamadı."
    except Exception as e:
        return False, str(e)

def get_ips_from_wazuh(host, port, username, password, min_level=3, limit=100):
    """
    Wazuh Manager üzerindeki alarmlardan (alerts) kaynak/hedef IP adreslerini çeker.
    min_level: Taranacak minimum kural seviyesi (Örn: 3 ve üzeri alarmlar)
    """
    try:
        token = get_wazuh_token(host, port, username, password)
    except Exception as e:
        print(f"[-] Wazuh bağlantı hatası: {e}")
        return []

    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://{host}:{port}/alerts"
    params = {
        "limit": limit,
        "sort": "-timestamp"
    }

    try:
        res = requests.get(url, headers=headers, params=params, verify=False, timeout=15)
        if res.status_code != 200:
            print(f"[-] Wazuh alarmları alınamadı ({res.status_code}): {res.text}")
            return []

        alerts_data = res.json().get("data", {}).get("affected_items", [])
        extracted_ips = set()

        for alert in alerts_data:
            rule_level = alert.get("rule", {}).get("level", 0)
            if rule_level < int(min_level):
                continue

            data_field = alert.get("data", {})
            
            # Kaynak veya hedef IP alanlarını kontrol et
            src_ip = data_field.get("srcip") or alert.get("srcip")
            dst_ip = data_field.get("dstip") or alert.get("dstip")

            for ip in [src_ip, dst_ip]:
                if ip and isinstance(ip, str):
                    # Yerel loopback adreslerini filtrele
                    clean_ip = ip.strip()
                    if clean_ip and not clean_ip.startswith("127."):
                        extracted_ips.add(clean_ip)

        return list(extracted_ips)
    except Exception as e:
        print(f"[-] Wazuh sorgu hatası: {e}")
        return []

if __name__ == "__main__":
    # Test amaçlı
    print("[*] Wazuh modülü hazır.")