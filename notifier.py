import subprocess
import platform

def send_macos_notification(title: str, subtitle: str, message: str):
    """macOS yerel bildirim merkezine sesli bildirim gönderir."""
    if platform.system() != "Darwin":
        return  # macOS haricinde sessizce atla
    
    # AppleScript ile yerel bildirim fırlatma
    script = f'''
    display notification "{message}" with title "{title}" subtitle "{subtitle}" sound name "Basso"
    '''
    try:
        subprocess.run(["osascript", "-e", script], check=True)
    except Exception as e:
        print(f"[-] Bildirim hatası: {e}")

def notify_critical_threats(critical_ips: list):
    """Kritik IP tespit edildiğinde analiste gerçek tehdit detaylarını fırlatır."""
    if not critical_ips:
        return

    count = len(critical_ips)
    if count == 1:
        ip_info = critical_ips[0]
        title = "🚨 KRİTİK TEHDİT TESPİT EDİLDİ"
        subtitle = f"IP: {ip_info.get('ip')}"
        message = (
            f"Skor: %{ip_info.get('abuse_score')} | "
            f"Ülke: {ip_info.get('country', 'Bilinmiyor')} | "
            f"ISP: {ip_info.get('isp', 'Bilinmiyor')}"
        )
    else:
        sample_ips = ", ".join([str(item.get('ip')) for item in critical_ips[:2]])
        title = "🚨 ÇOKLU KRİTİK TEHDİT"
        subtitle = f"{count} adet kritik zararlı IP yakalandı!"
        message = f"Tespit edilenler: {sample_ips}... Detaylar için paneli inceleyin."

    send_macos_notification(title, subtitle, message)