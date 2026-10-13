import os
import json
from pathlib import Path
import splunklib.client as client
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

def get_splunk_service(host=None, port=None, username=None, password=None):
    """Splunk REST API bağlantı objesini üretir."""
    load_dotenv(BASE_DIR / ".env", override=True)
    
    h = host or os.getenv("SPLUNK_HOST", "localhost")
    p = int(port or os.getenv("SPLUNK_PORT", 8089))
    u = username or os.getenv("SPLUNK_USERNAME", "admin")
    pwd = password or os.getenv("SPLUNK_PASSWORD", "")
    
    return client.connect(host=h, port=p, username=u, password=pwd, autologin=True)

def test_splunk_connection(host=None, port=None, username=None, password=None):
    """Masaüstü arayüzünden veya ayarlardan girilen bağlantıyı canlı test eder."""
    try:
        service = get_splunk_service(host, port, username, password)
        version = service.splunk_version
        return True, f"Bağlantı Başarılı! (Splunk v{version})"
    except Exception as e:
        return False, str(e)

def get_ips_from_splunk(index_name="ozer_mac_logs", time_range="0", host=None, port=None, username=None, password=None):
    """Splunk REST API üzerinden belirtilen index'teki benzersiz IP'leri çeker."""
    try:
        service = get_splunk_service(host, port, username, password)
    except Exception as e:
        print(f"[-] Splunk bağlantı hatası: {e}")
        return []

    search_query = rf'''
    search index={index_name} earliest={time_range}
    | rex max_match=0 "(?<extracted_ip>\b(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}\b)"
    | mvexpand extracted_ip
    | dedup extracted_ip
    | table extracted_ip
    '''

    try:
        job = service.jobs.create(search_query, exec_mode="blocking")
        result_stream = job.results(output_mode="json")
        raw_content = result_stream.read().decode("utf-8")
        
        ip_list = []
        if raw_content:
            parsed_json = json.loads(raw_content)
            rows = parsed_json.get("results", [])
            for row in rows:
                val = row.get("extracted_ip")
                if isinstance(val, list):
                    ip_list.extend(val)
                elif val:
                    ip_list.append(val)

        return list(set([ip.strip() for ip in ip_list if ip.strip()]))
    except Exception as e:
        print(f"[-] Splunk sorgu hatası: {e}")
        return []

def save_ips_to_file(ips, filename="ips.txt"):
    """IP listesini dosyaya kaydeder."""
    target_path = BASE_DIR / filename
    with open(target_path, "w", encoding="utf-8") as f:
        for ip in ips:
            f.write(f"{ip}\n")
    print(f"[+] {len(ips)} adet IP kaydedildi -> {target_path}")

if __name__ == "__main__":
    success, msg = test_splunk_connection()
    print("[*] Splunk Test Sonucu:", msg)