import sys
import socket
import requests
import json
import re
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

def get_session():
    ses = requests.Session()
    ses.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "*/*",
    })
    return ses

class ScanWorker(QThread):
    progress = pyqtSignal(str)
    done_info = pyqtSignal(dict)
    done_dns = pyqtSignal(dict)
    done_sub = pyqtSignal(list)
    done_url = pyqtSignal(list)
    done_red = pyqtSignal(list)
    done_phishing = pyqtSignal(list)
    finished = pyqtSignal(str)

    def __init__(self, domain):
        super().__init__()
        self.domain = domain
        self.stop = False
        self.ses = get_session()

    def stop_scan(self):
        self.stop = True

    def check(self):
        if self.stop:
            raise Exception("Scan dihentikan pengguna.")

    def run(self):
        try:
            self.scan_all()
        except Exception as e:
            self.finished.emit(str(e))

    def scan_all(self):
        domain = self.domain

        self.progress.emit("Mengambil info domain...")
        self.check()

        info = {}

        try:
            info["ip"] = socket.gethostbyname(domain)
        except:
            info["ip"] = None

        try:
            r = self.ses.get("https://" + domain, timeout=8)
            info["headers"] = dict(r.headers)
        except:
            info["headers"] = {}

        if info["ip"]:
            try:
                g = self.ses.get(f"https://ipinfo.io/{info['ip']}/json", timeout=8).json()
                info["geo"] = g
            except:
                info["geo"] = {}
        else:
            info["geo"] = {}

        self.done_info.emit(info)
        self.check()

        self.progress.emit("Mengambil DNS...")
        self.check()

        dns_data = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                ans = resolver.resolve(domain, rtype)
                dns_data[rtype] = [a.to_text() for a in ans]
            except:
                pass

        self.done_dns.emit(dns_data)
        self.check()

        self.progress.emit("Mengambil subdomain (5 sumber)...")
        self.check()

        subs = set()

        try:
            crt = self.ses.get(
                f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10
            ).json()
            for c in crt:
                for s in c["name_value"].split("\n"):
                    if domain in s:
                        subs.add(s.strip())
        except:
            pass

        try:
            ht = self.ses.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=6
            ).text
            for line in ht.splitlines():
                s = line.split(",")[0]
                if domain in s:
                    subs.add(s.strip())
        except:
            pass

        try:
            rd = self.ses.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=10
            ).text
            found = re.findall(r"<td>([\w\.\-]+)\." + domain + "</td>", rd)
            for f in found:
                subs.add(f + "." + domain)
        except:
            pass

        try:
            j = self.ses.get(
                f"https://jldc.me/anubis/subdomains/{domain}", timeout=10
            ).json()
            if isinstance(j, list):
                subs.update(j)
        except:
            pass

        try:
            a = self.ses.get(
                f"https://anubis-api.io/api/v1/domain/{domain}", timeout=10
            ).json()
            if "subdomains" in a:
                subs.update(a["subdomains"])
        except:
            pass

        subs = sorted(set(subs))
        self.done_sub.emit(subs)
        self.check()

        self.progress.emit("Crawling URL...")
        self.check()

        urls = set()

        def crawl(url):
            try:
                r = self.ses.get(url, timeout=10)
            except:
                return

            soup = BeautifulSoup(r.text, "html.parser")

            for tag in soup.find_all(["a", "script", "img", "iframe", "link"]):
                link = tag.get("href") or tag.get("src")
                if link:
                    full = urljoin(url, link)
                    if full.startswith("http"):
                        urls.add(full)

            reg = re.findall(r"https?://[^\s\"\'<>]+", r.text)
            urls.update(reg)

        crawl("https://" + domain)

        for s in subs[:8]:
            crawl("https://" + s)

        urls = sorted(urls)
        self.done_url.emit(urls)
        self.check()

        self.progress.emit("Mendeteksi redirect...")
        self.check()

        red = []
        for u in urls[:150]:
            try:
                r = self.ses.get(u, timeout=7, allow_redirects=True)
                if r.history:
                    if domain not in urlparse(r.url).netloc:
                        red.append((u, r.url))
            except:
                pass

        self.done_red.emit(red)
        self.check()

        self.progress.emit("Mendeteksi phishing...")
        self.check()

        keys = ["login", "verify", "secure", "account", "bank", "signin", "reset"]
        phi = []

        for u in urls:
            for k in keys:
                if k in u.lower():
                    if domain not in urlparse(u).netloc:
                        phi.append(u)
                        break

        self.done_phishing.emit(phi)
        self.check()

        self.finished.emit("Scan selesai.")


class ShadowScanGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SH4DOWSCAN-V2")
        self.setGeometry(250, 80, 1050, 700)

        layout = QVBoxLayout()

        # Input
        self.input = QLineEdit()
        self.input.setPlaceholderText("example.com")
        self.input.setFixedHeight(38)
        layout.addWidget(self.input)

        # Buttons
        h = QHBoxLayout()
        self.btn_scan = QPushButton("SCAN")
        self.btn_scan.clicked.connect(self.start)
        h.addWidget(self.btn_scan)

        self.btn_stop = QPushButton("STOP")
        self.btn_stop.clicked.connect(self.stop)
        self.btn_stop.setEnabled(False)
        h.addWidget(self.btn_stop)

        layout.addLayout(h)

        # Status
        self.status = QLabel("Status: -")
        layout.addWidget(self.status)

        # Tabs
        self.tabs = QTabWidget()
        self.tab_info = QTextEdit()
        self.tab_dns = QTextEdit()
        self.tab_sub = QTextEdit()
        self.tab_url = QTextEdit()
        self.tab_red = QTextEdit()
        self.tab_phi = QTextEdit()

        for tab in [
            self.tab_info, self.tab_dns, self.tab_sub,
            self.tab_url, self.tab_red, self.tab_phi
        ]:
            tab.setReadOnly(True)
            tab.setFont(QFont("Courier New", 11))
            tab.setLineWrapMode(QTextEdit.NoWrap)

        self.tabs.addTab(self.tab_info, "Info")
        self.tabs.addTab(self.tab_dns, "DNS")
        self.tabs.addTab(self.tab_sub, "Subdomain")
        self.tabs.addTab(self.tab_url, "URL")
        self.tabs.addTab(self.tab_red, "Redirect")
        self.tabs.addTab(self.tab_phi, "Phishing")

        layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.worker = None

    def start(self):
        domain = self.input.text().strip()
        if not domain:
            self.status.setText("Domain kosong.")
            return

        self.clear_tabs()

        self.worker = ScanWorker(domain)
        self.worker.progress.connect(self.update_status)

        self.worker.done_info.connect(lambda d: self.show_json(self.tab_info, d))
        self.worker.done_dns.connect(lambda d: self.show_json(self.tab_dns, d))
        self.worker.done_sub.connect(lambda d: self.show_json(self.tab_sub, d))
        self.worker.done_url.connect(lambda d: self.show_json(self.tab_url, d))
        self.worker.done_red.connect(lambda d: self.show_json(self.tab_red, d))
        self.worker.done_phishing.connect(lambda d: self.show_json(self.tab_phi, d))

        self.worker.finished.connect(self.finish)

        self.worker.start()
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status.setText("Scanning...")

    def stop(self):
        if self.worker:
            self.worker.stop_scan()
            self.status.setText("Menghentikan scan...")
            self.btn_stop.setEnabled(False)

    def finish(self, msg):
        self.status.setText(msg)
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def update_status(self, msg):
        self.status.setText("Status: " + msg)

    def clear_tabs(self):
        for t in [
            self.tab_info, self.tab_dns, self.tab_sub,
            self.tab_url, self.tab_red, self.tab_phi
        ]:
            t.clear()

    def show_json(self, widget, data):
        try:
            txt = json.dumps(data, indent=4, ensure_ascii=False)
        except:
            txt = str(data)
        widget.setPlainText(txt)


app = QApplication(sys.argv)
win = ShadowScanGUI()
win.show()
sys.exit(app.exec_())
