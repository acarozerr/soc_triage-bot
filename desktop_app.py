import os
import threading
from pathlib import Path
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import pandas as pd

from config_manager import load_config, save_config, is_configured
from splunk_collector import get_ips_from_splunk, save_ips_to_file, test_splunk_connection
from wazuh_collector import get_ips_from_wazuh, test_wazuh_connection
import main as triage_core
from reporter import export_as_csv, export_as_ioc_json, export_as_summary_text
from notifier import notify_critical_threats

BASE_DIR = Path(__file__).resolve().parent
REPORT_FILE = BASE_DIR / "triage_report.csv"

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SOARTriageApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SOC Triage & Automation Platform")
        self.geometry("1150x720")
        self.minsize(980, 620)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------- SOL YAN PANEL ----------------
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="🛡️ SOC SOAR", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Splunk Tetikleyici Buton
        self.btn_run_splunk = ctk.CTkButton(
            self.sidebar_frame, 
            text="🚀 Splunk Triyajı", 
            command=self.start_splunk_triage_thread,
            fg_color="#1f538d"
        )
        self.btn_run_splunk.grid(row=1, column=0, padx=20, pady=6)

        # Wazuh Tetikleyici Buton
        self.btn_run_wazuh = ctk.CTkButton(
            self.sidebar_frame, 
            text="🦅 Wazuh Triyajı", 
            command=self.start_wazuh_triage_thread,
            fg_color="#2b7a78"
        )
        self.btn_run_wazuh.grid(row=2, column=0, padx=20, pady=6)

        # Manuel IP
        self.manual_ip_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="Manuel IP (Örn: 8.8.8.8)")
        self.manual_ip_entry.grid(row=3, column=0, padx=20, pady=(15, 5))

        self.btn_manual_ip = ctk.CTkButton(
            self.sidebar_frame, 
            text="Tekil IP Tara", 
            command=self.start_manual_ip_thread,
            fg_color="#333333"
        )
        self.btn_manual_ip.grid(row=4, column=0, padx=20, pady=(0, 10))

        # Dışa Aktar
        self.btn_export = ctk.CTkButton(
            self.sidebar_frame,
            text="📥 Raporu Dışa Aktar",
            command=self.open_export_dialog,
            fg_color="#4B5563"
        )
        self.btn_export.grid(row=5, column=0, padx=20, pady=10)

        self.status_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Hazır", 
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.status_label.grid(row=9, column=0, padx=20, pady=15)

        # ---------------- SAĞ ALAN (TABVIEW) ----------------
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")

        self.tab_dashboard = self.tabview.add("📊 Dashboard & Rapor")
        self.tab_settings = self.tabview.add("⚙️ Entegrasyon & Ayarlar")

        self.setup_dashboard_tab()
        self.setup_settings_tab()

        self.after(150, self.check_initial_setup)

    def check_initial_setup(self):
        # Ayar olsun veya olmasın, CSV varsa tabloyu mutlaka doldur
        self.load_report_table()

        if not is_configured():
            self.tabview.set("⚙️ Entegrasyon & Ayarlar")
            self.set_status("⚠️ Yapılandırma gerekli")
        else:
            self.set_status("Hazır")

    def setup_dashboard_tab(self):
        self.tab_dashboard.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.tab_dashboard.grid_rowconfigure(2, weight=1)

        self.card_total = self.create_kpi_card(self.tab_dashboard, 0, "Toplam IP", "0", "gray")
        self.card_critical = self.create_kpi_card(self.tab_dashboard, 1, "Kritik Tehdit", "0", "#cf3a3a")
        self.card_suspicious = self.create_kpi_card(self.tab_dashboard, 2, "Şüpheli", "0", "#d48806")
        self.card_clean = self.create_kpi_card(self.tab_dashboard, 3, "Temiz", "0", "#389e0d")

        table_frame = ctk.CTkFrame(self.tab_dashboard)
        table_frame.grid(row=2, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("ip", "country", "isp", "abuse_score", "decision", "source", "timestamp")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, anchor="center", width=110)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # macOS Trackpad Kaydırma Desteği
        def _on_tree_scroll(event):
            if event.delta:
                self.tree.yview_scroll(int(-1 * event.delta), "units")

        self.tree.bind("<MouseWheel>", _on_tree_scroll)

    def create_kpi_card(self, parent, col, title, value, color):
        frame = ctk.CTkFrame(parent, fg_color="#1e1e24")
        frame.grid(row=0, column=col, padx=8, pady=10, sticky="nsew")
        lbl_title = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=12), text_color="gray")
        lbl_title.pack(pady=(10, 0))
        lbl_val = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=22, weight="bold"), text_color=color)
        lbl_val.pack(pady=(0, 10))
        return lbl_val

    def setup_settings_tab(self):
        cfg = load_config()

        container = ctk.CTkFrame(self.tab_settings, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=15)

        info_label = ctk.CTkLabel(
            container, 
            text="Entegrasyon ve Kimlik Yapılandırması", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        info_label.pack(anchor="w", pady=(0, 10))

        settings_tabs = ctk.CTkTabview(container)
        settings_tabs.pack(fill="both", expand=True, pady=(0, 15))

        tab_spl = settings_tabs.add("  Splunk SIEM  ")
        tab_waz = settings_tabs.add("  Wazuh REST API  ")
        tab_api = settings_tabs.add("  Tehdit İstihbaratı (API)  ")

        # 1. Splunk Sekmesi
        ctk.CTkLabel(tab_spl, text="Splunk Sunucu ve İndeks Bilgileri", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        self.entry_splunk_host = self.create_form_entry(tab_spl, "Splunk Host / IP:", cfg.get("SPLUNK_HOST", ""))
        self.entry_splunk_port = self.create_form_entry(tab_spl, "REST Port:", cfg.get("SPLUNK_PORT", "8089"))
        self.entry_splunk_user = self.create_form_entry(tab_spl, "Kullanıcı Adı:", cfg.get("SPLUNK_USERNAME", "admin"))
        self.entry_splunk_pass = self.create_form_entry(tab_spl, "Şifre:", cfg.get("SPLUNK_PASSWORD", ""), show="*")
        self.entry_splunk_index = self.create_form_entry(tab_spl, "Varsayılan Index:", cfg.get("SPLUNK_INDEX", ""))
        btn_test_spl = ctk.CTkButton(tab_spl, text="🔌 Splunk Bağlantısını Test Et", command=self.test_splunk, width=200, fg_color="#1f538d")
        btn_test_spl.pack(pady=20)

        # 2. Wazuh Sekmesi
        ctk.CTkLabel(tab_waz, text="Wazuh Manager API Erişimi", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        self.entry_wazuh_host = self.create_form_entry(tab_waz, "Wazuh Host / IP:", cfg.get("WAZUH_HOST", ""))
        self.entry_wazuh_port = self.create_form_entry(tab_waz, "API Port:", cfg.get("WAZUH_PORT", "55000"))
        self.entry_wazuh_user = self.create_form_entry(tab_waz, "Kullanıcı Adı:", cfg.get("WAZUH_USERNAME", "wazuh-wui"))
        self.entry_wazuh_pass = self.create_form_entry(tab_waz, "Şifre:", cfg.get("WAZUH_PASSWORD", ""), show="*")
        self.entry_wazuh_level = self.create_form_entry(tab_waz, "Min Kural Seviyesi:", cfg.get("WAZUH_MIN_LEVEL", "3"))
        btn_test_wazuh = ctk.CTkButton(tab_waz, text="🦅 Wazuh Bağlantısını Test Et", command=self.test_wazuh, width=200, fg_color="#2b7a78")
        btn_test_wazuh.pack(pady=20)

        # 3. Tehdit İstihbaratı Sekmesi
        ctk.CTkLabel(tab_api, text="Harici İstihbarat Servisleri", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        self.entry_abuse = self.create_form_entry(tab_api, "AbuseIPDB API Key:", cfg.get("ABUSEIPDB_API_KEY", ""), show="*")
        self.entry_vt = self.create_form_entry(tab_api, "VirusTotal API Key:", cfg.get("VIRUSTOTAL_API_KEY", ""), show="*")
        info_api = ctk.CTkLabel(tab_api, text="💡 Bu anahtarlar IP ve hash istihbaratı sorgularında skorlama amacıyla kullanılır.", text_color="gray")
        info_api.pack(anchor="w", padx=15, pady=10)

        # Sabit Kaydet Butonu
        btn_save = ctk.CTkButton(
            container, 
            text="💾 Tüm Ayarları Kaydet ve Uygula", 
            fg_color="#238636", 
            command=self.save_settings,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        btn_save.pack(fill="x", pady=(0, 5))

    def create_form_entry(self, parent, label_text, default_val="", show=None):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(row, text=label_text, width=150, anchor="w").pack(side="left")
        entry = ctk.CTkEntry(row, show=show)
        entry.insert(0, default_val)
        entry.pack(side="right", fill="x", expand=True)
        return entry

    def set_status(self, text):
        self.status_label.configure(text=text)

    def test_splunk(self):
        h = self.entry_splunk_host.get().strip()
        p = self.entry_splunk_port.get().strip()
        u = self.entry_splunk_user.get().strip()
        pwd = self.entry_splunk_pass.get().strip()
        success, msg = test_splunk_connection(h, p, u, pwd)
        if success:
            messagebox.showinfo("Başarılı", f"Splunk bağlantısı kuruldu!\n{msg}")
        else:
            messagebox.showerror("Hata", f"Splunk bağlantı hatası:\n{msg}")

    def test_wazuh(self):
        h = self.entry_wazuh_host.get().strip()
        p = self.entry_wazuh_port.get().strip()
        u = self.entry_wazuh_user.get().strip()
        pwd = self.entry_wazuh_pass.get().strip()
        success, msg = test_wazuh_connection(h, p, u, pwd)
        if success:
            messagebox.showinfo("Başarılı", f"Wazuh bağlantısı kuruldu!\n{msg}")
        else:
            messagebox.showerror("Hata", f"Wazuh bağlantı hatası:\n{msg}")

    def save_settings(self):
        new_cfg = {
            "SPLUNK_HOST": self.entry_splunk_host.get().strip(),
            "SPLUNK_PORT": self.entry_splunk_port.get().strip(),
            "SPLUNK_USERNAME": self.entry_splunk_user.get().strip(),
            "SPLUNK_PASSWORD": self.entry_splunk_pass.get().strip(),
            "SPLUNK_INDEX": self.entry_splunk_index.get().strip(),
            "WAZUH_HOST": self.entry_wazuh_host.get().strip(),
            "WAZUH_PORT": self.entry_wazuh_port.get().strip(),
            "WAZUH_USERNAME": self.entry_wazuh_user.get().strip(),
            "WAZUH_PASSWORD": self.entry_wazuh_pass.get().strip(),
            "WAZUH_MIN_LEVEL": self.entry_wazuh_level.get().strip(),
            "ABUSEIPDB_API_KEY": self.entry_abuse.get().strip(),
            "VIRUSTOTAL_API_KEY": self.entry_vt.get().strip()
        }
        save_config(new_cfg)
        messagebox.showinfo("Kayıt Başarılı", "Tüm ayarlar başarıyla kaydedildi!")
        self.tabview.set("📊 Dashboard & Rapor")
        self.set_status("Hazır")

    def open_export_dialog(self):
        if not os.path.exists(REPORT_FILE):
            messagebox.showwarning("Rapor Yok", "Dışa aktarılacak analiz verisi bulunamadı.")
            return

        df = pd.read_csv(REPORT_FILE)
        if df.empty:
            messagebox.showwarning("Boş Rapor", "Rapor dosyası boş.")
            return

        file_types = [
            ("Özet Metin Raporu (*.txt)", "*.txt"),
            ("IoC Tehdit Listesi (*.json)", "*.json"),
            ("Ham CSV Tablosu (*.csv)", "*.csv")
        ]

        save_path = filedialog.asksaveasfilename(
            title="Triyaj Raporunu Kaydet",
            defaultextension=".txt",
            filetypes=file_types
        )

        if not save_path:
            return

        try:
            if save_path.endswith(".json"):
                export_as_ioc_json(df, save_path)
            elif save_path.endswith(".csv"):
                export_as_csv(df, save_path)
            else:
                export_as_summary_text(df, save_path)
            
            messagebox.showinfo("Başarılı", f"Rapor başarıyla kaydedildi:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor dışa aktarılırken hata oluştu:\n{e}")

    # SPLUNK İŞLEMLERİ
    def start_splunk_triage_thread(self):
        threading.Thread(target=self.run_splunk_triage, daemon=True).start()

    def run_splunk_triage(self):
        self.btn_run_splunk.configure(state="disabled")
        self.set_status("Splunk taranıyor...")
        
        cfg = load_config()
        ips = get_ips_from_splunk(
            index_name=cfg.get("SPLUNK_INDEX"),
            host=cfg.get("SPLUNK_HOST"),
            port=cfg.get("SPLUNK_PORT"),
            username=cfg.get("SPLUNK_USERNAME"),
            password=cfg.get("SPLUNK_PASSWORD")
        )

        if ips:
            self.set_status(f"{len(ips)} IP bulundu, triyajlanıyor...")
            save_ips_to_file(ips)
            
            if hasattr(triage_core, "process_ip_list"):
                triage_core.process_ip_list()
            elif hasattr(triage_core, "main"):
                triage_core.main()

            self.load_report_table()
            self.check_and_trigger_notifications()
            self.set_status("Splunk triyajı tamamlandı.")
        else:
            self.set_status("Splunk'ta IP bulunamadı.")
            messagebox.showwarning("Sonuç Yok", "Belirtilen index'te IP bulunamadı.")

        self.btn_run_splunk.configure(state="normal")

    # WAZUH İŞLEMLERİ
    def start_wazuh_triage_thread(self):
        threading.Thread(target=self.run_wazuh_triage, daemon=True).start()

    def run_wazuh_triage(self):
        self.btn_run_wazuh.configure(state="disabled")
        self.set_status("Wazuh alarmları taranıyor...")

        cfg = load_config()
        ips = get_ips_from_wazuh(
            host=cfg.get("WAZUH_HOST"),
            port=cfg.get("WAZUH_PORT", "55000"),
            username=cfg.get("WAZUH_USERNAME"),
            password=cfg.get("WAZUH_PASSWORD"),
            min_level=cfg.get("WAZUH_MIN_LEVEL", "3")
        )

        if ips:
            self.set_status(f"{len(ips)} IP yakalandı, triyajlanıyor...")
            save_ips_to_file(ips)

            if hasattr(triage_core, "process_ip_list"):
                triage_core.process_ip_list()
            elif hasattr(triage_core, "main"):
                triage_core.main()

            self.load_report_table()
            self.check_and_trigger_notifications()
            self.set_status("Wazuh triyajı tamamlandı.")
        else:
            self.set_status("Wazuh'ta IP bulunamadı.")
            messagebox.showwarning("Sonuç Yok", "Wazuh alarmlarında eşleşen IP adresi bulunamadı.")

        self.btn_run_wazuh.configure(state="normal")

    # MANUEL IP
    def start_manual_ip_thread(self):
        ip = self.manual_ip_entry.get().strip()
        if not ip:
            return
        threading.Thread(target=self.run_manual_ip, args=(ip,), daemon=True).start()

    def run_manual_ip(self, ip):
        self.set_status(f"{ip} analiz ediliyor...")
        save_ips_to_file([ip])
        if hasattr(triage_core, "process_ip_list"):
            triage_core.process_ip_list()
        elif hasattr(triage_core, "main"):
            triage_core.main()

        self.load_report_table()
        self.check_and_trigger_notifications()
        self.set_status("Analiz tamamlandı.")

    def check_and_trigger_notifications(self):
        if not os.path.exists(REPORT_FILE):
            return
        try:
            df = pd.read_csv(REPORT_FILE)
            if df.empty or "decision" not in df.columns:
                return
            
            criticals = df[df["decision"] == "CRITICAL"].to_dict(orient="records")
            if criticals:
                notify_critical_threats(criticals)
        except Exception as e:
            print(f"[-] Bildirim kontrol hatası: {e}")

    def load_report_table(self):
        if not os.path.exists(REPORT_FILE):
            return

        try:
            df = pd.read_csv(REPORT_FILE)
            if df.empty:
                return

            for item in self.tree.get_children():
                self.tree.delete(item)

            for _, row in df.iterrows():
                values = [
                    row.get("ip", ""),
                    row.get("country", ""),
                    row.get("isp", ""),
                    row.get("abuse_score", 0),
                    row.get("decision", ""),
                    row.get("source", ""),
                    row.get("timestamp", "")
                ]
                self.tree.insert("", "end", values=values)

            self.card_total.configure(text=str(len(df)))
            self.card_critical.configure(text=str(len(df[df["decision"] == "CRITICAL"])))
            self.card_suspicious.configure(text=str(len(df[df["decision"] == "SUSPICIOUS"])))
            self.card_clean.configure(text=str(len(df[df["decision"] == "CLEAN"])))
        except Exception:
            pass

if __name__ == "__main__":
    app = SOARTriageApp()
    app.mainloop()