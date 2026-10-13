import os
import streamlit as st
import pandas as pd
import plotly.express as px
from splunk_collector import get_ips_from_splunk, save_ips_to_file
import main as triage_core

# Sayfa Ayarları
st.set_page_config(
    page_title="SOC Triage Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("SOC Tehdit İstihbaratı & Triyaj Paneli")
st.markdown("Splunk, AbuseIPDB ve VirusTotal entegrasyonlu otomatik triyaj sistemi.")

REPORT_FILE = "triage_report.csv"

# ==========================================
# SOL YAN PANEL (KONTROL VE TETİKLEME)
# ==========================================
with st.sidebar:
    st.header("⚡ İşlem Kontrolleri")
    
    st.subheader("1. Splunk Entegrasyonu")
    splunk_index = st.text_input("Splunk Index Adı:", value="ozer_mac_logs")
    
    if st.button("🚀 Splunk'tan Çek ve Triyajla", type="primary"):
        with st.status("Pipeline çalışıyor...", expanded=True) as status:
            st.write("🔍 Splunk REST API'ye bağlanılıyor...")
            ips = get_ips_from_splunk(index_name=splunk_index, time_range="0")
            
            if ips:
                st.write(f"✅ {len(ips)} adet IP bulundu, ips.txt güncelleniyor...")
                save_ips_to_file(ips)
                
                st.write("🧠 AbuseIPDB & VirusTotal triyajı yürütülüyor...")
                if hasattr(triage_core, "process_ip_list"):
                    triage_core.process_ip_list()
                elif hasattr(triage_core, "main"):
                    triage_core.main()
                
                status.update(label="Triyaj Başarıyla Tamamlandı!", state="complete", expanded=False)
                st.success("Veriler güncellendi! Dashboard yenileniyor...")
                st.rerun()
            else:
                status.update(label="IP Bulunamadı", state="error", expanded=False)
                st.warning("Belirtilen index'te uygun IP adresi bulunamadı.")

    st.divider()

    st.subheader("2. Manuel Tekil IP Sorgula")
    manual_ip = st.text_input("IP Adresi Girin:", placeholder="Örn: 185.220.101.5")
    if st.button("Tekil IP Analiz Et"):
        if manual_ip.strip():
            save_ips_to_file([manual_ip.strip()])
            if hasattr(triage_core, "process_ip_list"):
                triage_core.process_ip_list()
            elif hasattr(triage_core, "main"):
                triage_core.main()
            st.success(f"{manual_ip} triyajlandı!")
            st.rerun()

st.divider()

# ==========================================
# ANA PANEL: METRİKLER VE GÖRSELLEŞTİRME
# ==========================================
if not os.path.exists(REPORT_FILE):
    st.info("ℹ️ Henüz bir rapor dosyası (`triage_report.csv`) bulunmuyor. Sol menüden Splunk triyajını başlatabilirsiniz.")
    st.stop()

df = pd.read_csv(REPORT_FILE)

if df.empty:
    st.warning("⚠️ Rapor dosyası boş.")
    st.stop()

# --- KPI METRİKLERİ ---
toplam_ip = len(df)
kritik_ip = len(df[df["decision"] == "CRITICAL"]) if "decision" in df.columns else 0
supheli_ip = len(df[df["decision"] == "SUSPICIOUS"]) if "decision" in df.columns else 0
temiz_ip = len(df[df["decision"] == "CLEAN"]) if "decision" in df.columns else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Toplam Analiz Edilen IP", toplam_ip)
col2.metric("🚨 Kritik Tehdit", kritik_ip)
col3.metric("⚠️ Şüpheli Aktivite", supheli_ip)
col4.metric("✅ Güvenli IP", temiz_ip)

st.divider()

# --- GRAFİK ALANI ---
col_grafik1, col_grafik2 = st.columns(2)

with col_grafik1:
    if "decision" in df.columns:
        fig_pasta = px.pie(
            df, 
            names="decision", 
            title="Tehdit Seviyesi Dağılımı",
            color="decision",
            color_discrete_map={"CRITICAL": "#FF4B4B", "SUSPICIOUS": "#FFA500", "CLEAN": "#00CC96"}
        )
        st.plotly_chart(fig_pasta, use_container_width=True)

with col_grafik2:
    if "country" in df.columns:
        ulke_sayilari = df["country"].value_counts().reset_index()
        ulke_sayilari.columns = ["country", "count"]
        fig_bar = px.bar(
            ulke_sayilari, 
            x="country", 
            y="count", 
            title="Taranan IP'lerin Ülke Dağılımı",
            labels={"country": "Ülke Kodu", "count": "IP Sayısı"}
        )
        st.plotly_chart(fig_bar, use_container_width=True)

st.divider()

# --- TABLO VE FİLTRE ---
st.subheader("📋 Ayrıntılı IP Triyaj Listesi")

if "decision" in df.columns:
    secilen_filtre = st.selectbox(
        "Karara Göre Filtrele:",
        options=["TÜMÜ", "CRITICAL", "SUSPICIOUS", "CLEAN"]
    )
    if secilen_filtre != "TÜMÜ":
        gosterilecek_df = df[df["decision"] == secilen_filtre]
    else:
        gosterilecek_df = df
else:
    gosterilecek_df = df

def highlight_decision(val):
    if val == "CRITICAL":
        return "background-color: #7d1a1a; color: white; font-weight: bold;"
    elif val == "SUSPICIOUS":
        return "background-color: #7d5a1a; color: white;"
    elif val == "CLEAN":
        return "background-color: #1a5e35; color: white;"
    return ""

if "decision" in gosterilecek_df.columns:
    st.dataframe(
        gosterilecek_df.style.map(highlight_decision, subset=["decision"]),
        use_container_width=True
    )
else:
    st.dataframe(gosterilecek_df, use_container_width=True)