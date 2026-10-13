import json
import pandas as pd
from datetime import datetime
from pathlib import Path

def export_as_csv(df: pd.DataFrame, target_path: str):
    """Veriyi doğrudan CSV olarak kaydeder."""
    df.to_csv(target_path, index=False, encoding="utf-8")
    return True

def export_as_ioc_json(df: pd.DataFrame, target_path: str):
    """Kritik ve şüpheli IP'leri IoC bloklama formatında JSON olarak kaydeder."""
    threat_df = df[df["decision"].isin(["CRITICAL", "SUSPICIOUS"])]
    
    ioc_data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_threats_found": len(threat_df),
        "iocs": []
    }
    
    for _, row in threat_df.iterrows():
        ioc_data["iocs"].append({
            "ip": row.get("ip"),
            "severity": row.get("decision"),
            "abuse_score": int(row.get("abuse_score", 0)),
            "country": row.get("country", "Unknown"),
            "isp": row.get("isp", "Unknown"),
            "timestamp": row.get("timestamp")
        })
        
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(ioc_data, f, indent=4)
    return True

def export_as_summary_text(df: pd.DataFrame, target_path: str):
    """Yönetici ve analist için okunabilir vaka özet raporu üretir."""
    total = len(df)
    critical = len(df[df["decision"] == "CRITICAL"]) if "decision" in df.columns else 0
    suspicious = len(df[df["decision"] == "SUSPICIOUS"]) if "decision" in df.columns else 0
    clean = len(df[df["decision"] == "CLEAN"]) if "decision" in df.columns else 0
    
    lines = [
        "=" * 60,
        "          SOC SOAR - TEHDİT TRİYAJ RAPORU",
        "=" * 60,
        f"Tarih/Saat : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Toplam IP  : {total}",
        f"🚨 Kritik  : {critical}",
        f"⚠️ Şüpheli : {suspicious}",
        f"✅ Temiz   : {clean}",
        "-" * 60,
        "TESPİT EDİLEN TEHDİTLER & DETAYLAR:",
        "-" * 60
    ]
    
    threats = df[df["decision"].isin(["CRITICAL", "SUSPICIOUS"])]
    if threats.empty:
        lines.append("Herhangi bir kritik veya şüpheli IP tespit edilmedi.")
    else:
        for _, row in threats.iterrows():
            lines.append(
                f"[{row.get('decision')}] {row.get('ip')} | Ülke: {row.get('country')} | "
                f"Skor: %{row.get('abuse_score')} | ISP: {row.get('isp')}"
            )
            
    lines.append("=" * 60)
    
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return True