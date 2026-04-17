import sys
import os
import time
import socket
import ssl
import ipaddress
import threading
import re
import base64
from urllib.parse import urlparse, quote
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from urllib.request import Request, urlopen

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QCheckBox,
    QScrollArea, QGridLayout, QProgressBar, QGroupBox
)


TEST_HOST = "speed.cloudflare.com"
DOWNLOAD_PATH = "/__down?bytes=50000000"


def format_ip_port(ip: str, port: int) -> str:
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def split_countries(country_text: str):
    if not country_text.strip():
        return []
    parts = country_text.replace("，", ",").split(",")
    result = []
    seen = set()
    for part in parts:
        code = part.strip().upper()
        if code and code not in seen:
            seen.add(code)
            result.append(code)
    return result


def extract_country_code(text: str):
    if not text:
        return "UNKNOWN"

    text_up = text.upper().strip()

    m = re.search(r'#([A-Z]{2})\b', text_up)
    if m:
        return m.group(1)

    country_candidates = {
        "HK", "JP", "SG", "TW", "US", "KR", "DE", "FR", "GB", "UK",
        "NL", "CA", "AU", "IN", "RU", "BR", "IT", "ES", "VN", "TH",
        "MY", "PH", "ID", "MO"
    }

    parts = re.split(r'[^A-Z]+', text_up)
    for part in parts:
        if part in country_candidates:
            return part

    m = re.search(r'(?:COUNTRY|LOC|REGION|CODE)=([A-Z]{2})\b', text_up)
    if m and m.group(1) in country_candidates:
        return m.group(1)

    return "UNKNOWN"


def parse_ip_port_country_line(line: str, default_port: int = 443):
    original_line = line.rstrip("\n").rstrip("\r")
    line = original_line.strip()
    if not line:
        return None

    raw_line = line
    country = "UNKNOWN"

    if "#" in line:
        line_part, country_part = line.split("#", 1)
        line = line_part.strip()
        country_part = country_part.strip().upper()
        m = re.match(r'^([A-Z]{2})', country_part)
        if m:
            country = m.group(1)

    if country == "UNKNOWN":
        country = extract_country_code(raw_line)

    if not line:
        return None

    # URL
    if "://" in line:
        try:
            parsed = urlparse(line)
            host = parsed.hostname
            port = parsed.port or default_port
            if not host:
                return None

            resolved_ip = host
            try:
                ipaddress.ip_address(host)
                resolved_ip = host
            except Exception:
                resolved_ip = socket.gethostbyname(host)

            return {
                "ip": resolved_ip,
                "host": host,
                "port": port,
                "country": country,
                "raw_line": original_line,
            }
        except Exception:
            return None

    # [IPv6]:port
    if line.startswith("[") and "]" in line:
        try:
            host_part, rest = line.split("]", 1)
            ip = host_part[1:].strip()
            port = default_port
            if rest.startswith(":"):
                port = int(rest[1:].strip())
            ipaddress.ip_address(ip)
            return {
                "ip": ip,
                "host": ip,
                "port": port,
                "country": country,
                "raw_line": original_line,
            }
        except Exception:
            return None

    # 纯IP
    try:
        ipaddress.ip_address(line)
        return {
            "ip": line,
            "host": line,
            "port": default_port,
            "country": country,
            "raw_line": original_line,
        }
    except Exception:
        pass

    # IPv4:port / 域名:port
    if ":" in line:
        try:
            host, port = line.rsplit(":", 1)
            host = host.strip()
            port = int(port.strip())

            resolved_ip = host
            try:
                ipaddress.ip_address(host)
                resolved_ip = host
            except Exception:
                resolved_ip = socket.gethostbyname(host)

            return {
                "ip": resolved_ip,
                "host": host,
                "port": port,
                "country": country,
                "raw_line": original_line,
            }
        except Exception:
            return None

    # 域名
    try:
        ip = socket.gethostbyname(line)
        return {
            "ip": ip,
            "host": line,
            "port": default_port,
            "country": country,
            "raw_line": original_line,
        }
    except Exception:
        return None


def tcp_ping(ip: str, port: int, timeout=1.5):
    start = time.time()
    try:
        if ":" in ip:
            addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addrinfo[0]
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None


def download_speed_test(ip: str, port: int, stop_event: threading.Event):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = (
        f"GET {DOWNLOAD_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    speed = 0.0
    try:
        if ":" in ip:
            addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addrinfo[0]
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(3)
            sock.connect(sockaddr)
        else:
            sock = socket.create_connection((ip, port), timeout=3)

        ss = ctx.wrap_socket(sock, server_hostname=TEST_HOST)
        ss.settimeout(3)
        ss.sendall(req)

        start = time.time()
        header_data = b""
        header_done = False
        body_size = 0

        while time.time() - start < 3:
            if stop_event.is_set():
                break
            try:
                buf = ss.recv(8192)
                if not buf:
                    break
                if not header_done:
                    header_data += buf
                    if b"\r\n\r\n" in header_data:
                        header_done = True
                        body = header_data.split(b"\r\n\r\n", 1)[1]
                        body_size += len(body)
                else:
                    body_size += len(buf)
            except socket.timeout:
                break

        ss.close()
        duration = time.time() - start
        speed = round((body_size / 1024 / 1024) / max(duration, 0.1), 2)
    except Exception:
        speed = 0.0

    return speed


def fetch_text_from_url(url: str):
    req = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/plain,*/*"
        }
    )
    with urlopen(req, timeout=15) as resp:
        data = resp.read()
        charset = "utf-8"
        content_type = resp.headers.get_content_charset()
        if content_type:
            charset = content_type
        try:
            return data.decode(charset, errors="ignore")
        except Exception:
            return data.decode("utf-8", errors="ignore")


def ensure_txt_filename(name: str):
    name = name.strip()
    if not name:
        name = "export_result"
    if not name.lower().endswith(".txt"):
        name += ".txt"
    return name


def build_export_text(items):
    lines = []
    for item in items:
        raw_line = item.get("raw_line", "").strip()
        if raw_line:
            lines.append(raw_line)
        else:
            ip_port = format_ip_port(item["ip"], item["port"])
            lines.append(f"{ip_port}#{item.get('country', 'UNKNOWN')}")
    return "\n".join(lines) + "\n"


def upload_to_webdav(base_url: str, remote_dir: str, filename: str, content: bytes, username: str, password: str):
    base_url = base_url.strip().rstrip("/")
    remote_dir = remote_dir.strip().strip("/")
    filename_encoded = quote(filename)

    if remote_dir:
        full_url = f"{base_url}/{remote_dir}/{filename_encoded}"
    else:
        full_url = f"{base_url}/{filename_encoded}"

    req = Request(full_url, data=content, method="PUT")
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    req.add_header("Content-Length", str(len(content)))

    with urlopen(req, timeout=30) as resp:
        return resp.status, full_url


class LoadUrlWorker(QThread):
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def run(self):
        try:
            self.log.emit(f"开始加载远程TXT：{self.url}")
            text = fetch_text_from_url(self.url)
            self.finished_signal.emit(True, text)
        except Exception as e:
            self.finished_signal.emit(False, str(e))


class LatencyTestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    finished_signal = pyqtSignal(list)

    def __init__(self, targets, threads=20):
        super().__init__()
        self.targets = targets
        self.threads = threads
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        if not self.targets:
            self.log.emit("没有可测试的目标。")
            self.finished_signal.emit([])
            return

        self.log.emit(f"已选择 {len(self.targets)} 个目标，开始延迟测试...")
        results = []
        completed = 0

        def ping_one(item):
            latency = tcp_ping(item["ip"], item["port"], timeout=1.5)
            if latency is None:
                return None
            result = dict(item)
            result["latency"] = latency
            result["download_speed"] = 0.0
            return result

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(ping_one, item): item for item in self.targets}
            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    self.log.emit("延迟测试已停止。")
                    break

                completed += 1
                self.progress.emit(completed, len(self.targets))

                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        self.log.emit(
                            f"[{completed}/{len(self.targets)}] "
                            f"{format_ip_port(result['ip'], result['port'])} | "
                            f"{result['country']} | {result['latency']:.2f} ms"
                        )
                    else:
                        item = future_map[future]
                        self.log.emit(
                            f"[{completed}/{len(self.targets)}] "
                            f"{format_ip_port(item['ip'], item['port'])} | "
                            f"{item['country']} | 无延迟，已过滤"
                        )
                except Exception as e:
                    self.log.emit(f"[{completed}/{len(self.targets)}] 延迟测试异常: {e}")

        results.sort(key=lambda x: x["latency"])
        self.finished_signal.emit(results)


class SpeedTestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    finished_signal = pyqtSignal(list)

    def __init__(self, targets, threads=20):
        super().__init__()
        self.targets = targets
        self.threads = threads
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        if not self.targets:
            self.log.emit("没有可测速的节点，请先进行延迟测试。")
            self.finished_signal.emit([])
            return

        self.log.emit(f"开始对 {len(self.targets)} 个有延迟节点进行测速...")
        results = []
        completed = 0

        def speed_one(item):
            result = dict(item)
            speed = download_speed_test(item["ip"], item["port"], self.stop_event)
            result["download_speed"] = speed
            return result

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(speed_one, item): item for item in self.targets}
            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    self.log.emit("测速已停止。")
                    break

                completed += 1
                self.progress.emit(completed, len(self.targets))

                try:
                    result = future.result()
                    results.append(result)
                    self.log.emit(
                        f"[{completed}/{len(self.targets)}] "
                        f"{format_ip_port(result['ip'], result['port'])} | "
                        f"{result['country']} | "
                        f"{result['latency']:.2f} ms | "
                        f"{result['download_speed']:.2f} MB/s"
                    )
                except Exception as e:
                    self.log.emit(f"[{completed}/{len(self.targets)}] 测速异常: {e}")

        results.sort(key=lambda x: x["download_speed"], reverse=True)
        self.finished_signal.emit(results)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("国家分组测速工具 - WebDAV增强版")
        self.resize(1280, 860)

        self.all_targets = []
        self.country_checkboxes = {}
        self.latency_results = []
        self.results = []
        self.worker = None
        self.url_loader = None

        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("国家分组测速工具 - WebDAV增强版")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # 导入设置
        import_group = QGroupBox("导入设置")
        import_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("请选择本地TXT文件...")
        btn_browse = QPushButton("选择本地文件")
        btn_browse.clicked.connect(self.choose_file)
        row1.addWidget(QLabel("本地TXT:"))
        row1.addWidget(self.file_edit)
        row1.addWidget(btn_browse)
        import_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("输入TXT链接，例如：https://zip.cm.edu.kg/all.txt")
        btn_load_url = QPushButton("加载TXT链接")
        btn_load_url.clicked.connect(self.load_url_text)
        row2.addWidget(QLabel("TXT链接:"))
        row2.addWidget(self.url_edit)
        row2.addWidget(btn_load_url)
        import_layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)

        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 500)
        self.thread_input.setValue(20)

        self.country_input = QLineEdit()
        self.country_input.setPlaceholderText("导出筛选国家，留空=全部，例如：HK,JP,SG")

        self.topn_input = QSpinBox()
        self.topn_input.setRange(0, 100000)
        self.topn_input.setValue(10)
        self.topn_input.setToolTip("每国导出前N条，0表示全部")

        row3.addWidget(QLabel("默认端口:"))
        row3.addWidget(self.port_input)
        row3.addSpacing(12)
        row3.addWidget(QLabel("线程数:"))
        row3.addWidget(self.thread_input)
        row3.addSpacing(12)
        row3.addWidget(QLabel("导出筛选国家:"))
        row3.addWidget(self.country_input)
        row3.addSpacing(12)
        row3.addWidget(QLabel("每国前N条:"))
        row3.addWidget(self.topn_input)

        import_layout.addLayout(row3)
        import_group.setLayout(import_layout)
        main_layout.addWidget(import_group)

        # 国家选择
        country_group = QGroupBox("国家选择")
        country_main_layout = QVBoxLayout()

        top_country_row = QHBoxLayout()
        self.country_search_edit = QLineEdit()
        self.country_search_edit.setPlaceholderText("搜索国家代码，例如 HK / JP / US")
        self.country_search_edit.textChanged.connect(self.filter_country_checkboxes)

        self.btn_select_all_country = QPushButton("全选")
        self.btn_unselect_all_country = QPushButton("全不选")
        self.btn_select_all_country.clicked.connect(self.select_all_countries)
        self.btn_unselect_all_country.clicked.connect(self.unselect_all_countries)

        top_country_row.addWidget(QLabel("国家搜索:"))
        top_country_row.addWidget(self.country_search_edit)
        top_country_row.addWidget(self.btn_select_all_country)
        top_country_row.addWidget(self.btn_unselect_all_country)
        country_main_layout.addLayout(top_country_row)

        self.country_scroll = QScrollArea()
        self.country_scroll.setWidgetResizable(True)
        self.country_scroll.setFixedHeight(160)

        self.country_widget = QWidget()
        self.country_layout = QGridLayout()
        self.country_layout.setSpacing(10)
        self.country_widget.setLayout(self.country_layout)
        self.country_scroll.setWidget(self.country_widget)

        country_main_layout.addWidget(self.country_scroll)
        country_group.setLayout(country_main_layout)
        main_layout.addWidget(country_group)

        # 导出设置
        export_group = QGroupBox("导出设置")
        export_layout = QVBoxLayout()

        export_row1 = QHBoxLayout()
        self.export_name_edit = QLineEdit()
        self.export_name_edit.setPlaceholderText("导出文件名，例如 result.txt")
        self.export_name_edit.setText("export_result.txt")
        export_row1.addWidget(QLabel("导出文件名:"))
        export_row1.addWidget(self.export_name_edit)
        export_layout.addLayout(export_row1)

        export_row2 = QHBoxLayout()
        self.webdav_url_edit = QLineEdit()
        self.webdav_url_edit.setPlaceholderText("WebDAV地址，例如：https://dav.example.com/dav")
        export_row2.addWidget(QLabel("WebDAV地址:"))
        export_row2.addWidget(self.webdav_url_edit)
        export_layout.addLayout(export_row2)

        export_row3 = QHBoxLayout()
        self.webdav_user_edit = QLineEdit()
        self.webdav_user_edit.setPlaceholderText("WebDAV用户名")
        self.webdav_pass_edit = QLineEdit()
        self.webdav_pass_edit.setPlaceholderText("WebDAV密码")
        self.webdav_pass_edit.setEchoMode(QLineEdit.Password)
        export_row3.addWidget(QLabel("用户名:"))
        export_row3.addWidget(self.webdav_user_edit)
        export_row3.addWidget(QLabel("密码:"))
        export_row3.addWidget(self.webdav_pass_edit)
        export_layout.addLayout(export_row3)

        export_row4 = QHBoxLayout()
        self.webdav_dir_edit = QLineEdit()
        self.webdav_dir_edit.setPlaceholderText("远程目录，例如：测速结果/2025/04")
        export_row4.addWidget(QLabel("远程目录:"))
        export_row4.addWidget(self.webdav_dir_edit)
        export_layout.addLayout(export_row4)

        export_group.setLayout(export_layout)
        main_layout.addWidget(export_group)

        # 操作
        action_group = QGroupBox("操作")
        action_layout = QVBoxLayout()

        row_action = QHBoxLayout()
        self.btn_latency = QPushButton("延迟测试")
        self.btn_speed = QPushButton("测速")
        self.btn_stop = QPushButton("停止")
        self.btn_export = QPushButton("导出到本地")
        self.btn_export_webdav = QPushButton("导出到WebDAV")
        self.btn_clear = QPushButton("清空结果")

        self.btn_latency.clicked.connect(self.start_latency_test)
        self.btn_speed.clicked.connect(self.start_speed_test)
        self.btn_stop.clicked.connect(self.stop_test)
        self.btn_export.clicked.connect(self.export_results_local)
        self.btn_export_webdav.clicked.connect(self.export_results_webdav)
        self.btn_clear.clicked.connect(self.clear_results)

        self.btn_speed.setEnabled(False)

        row_action.addWidget(self.btn_latency)
        row_action.addWidget(self.btn_speed)
        row_action.addWidget(self.btn_stop)
        row_action.addWidget(self.btn_export)
        row_action.addWidget(self.btn_export_webdav)
        row_action.addWidget(self.btn_clear)
        row_action.addStretch()
        action_layout.addLayout(row_action)

        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_label = QLabel("进度：0/0")
        self.status_label = QLabel("状态：空闲")
        progress_row.addWidget(self.progress_bar)
        progress_row.addWidget(self.progress_label)
        progress_row.addWidget(self.status_label)
        action_layout.addLayout(progress_row)

        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # 日志
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        self.setLayout(main_layout)

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1f26;
                color: #e8e8e8;
                font-size: 13px;
            }
            QGroupBox {
                border: 1px solid #3a3d4a;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 12px;
                font-weight: bold;
                background-color: #252733;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px 0 6px;
                color: #7cc7ff;
            }
            QLabel#titleLabel {
                font-size: 24px;
                font-weight: bold;
                color: #7cc7ff;
                padding: 8px;
            }
            QLineEdit, QSpinBox, QTextEdit {
                background-color: #2b2d3a;
                border: 1px solid #44485a;
                border-radius: 8px;
                padding: 6px;
                color: #ffffff;
            }
            QPushButton {
                background-color: #3d7eff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5a92ff;
            }
            QPushButton:pressed {
                background-color: #2f66d0;
            }
            QPushButton:disabled {
                background-color: #666a7a;
                color: #cccccc;
            }
            QProgressBar {
                border: 1px solid #44485a;
                border-radius: 8px;
                text-align: center;
                background-color: #2b2d3a;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #00c853;
                border-radius: 8px;
            }
            QScrollArea {
                border: 1px solid #44485a;
                border-radius: 8px;
                background-color: #2b2d3a;
            }
            QCheckBox {
                spacing: 8px;
            }
        """)

    def append_log(self, text):
        self.log_edit.append(text)

    def set_status(self, text):
        self.status_label.setText(f"状态：{text}")

    def reset_progress(self):
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self.progress_label.setText("进度：0/0")

    def update_progress(self, current, total):
        self.progress_bar.setMaximum(total if total > 0 else 1)
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"进度：{current}/{total}")

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择TXT文件", "", "Text Files (*.txt);;All Files (*)")
        if not path:
            return
        self.file_edit.setText(path)
        self.log_edit.clear()
        ok = self.load_targets_from_file(path)
        if ok:
            self.append_log(f"本地文件加载完成，共解析到 {len(self.all_targets)} 个目标。")
            self.set_status("已加载本地TXT")

    def load_targets_from_file(self, path):
        if not os.path.exists(path):
            QMessageBox.warning(self, "提示", "文件不存在。")
            return False

        self.all_targets = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                item = parse_ip_port_country_line(line, self.port_input.value())
                if item:
                    self.all_targets.append(item)

        if not self.all_targets:
            QMessageBox.warning(self, "提示", "没有解析到可用目标。")
            return False

        self.build_country_checkboxes()
        return True

    def load_url_text(self):
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入TXT链接。")
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            QMessageBox.warning(self, "提示", "链接必须以 http:// 或 https:// 开头。")
            return

        self.log_edit.clear()
        self.set_status("正在加载远程TXT")
        self.url_loader = LoadUrlWorker(url)
        self.url_loader.log.connect(self.append_log)
        self.url_loader.finished_signal.connect(self.on_url_loaded)
        self.url_loader.start()

    def on_url_loaded(self, success, content):
        if not success:
            QMessageBox.warning(self, "提示", f"远程TXT加载失败：\n{content}")
            self.set_status("远程TXT加载失败")
            return

        self.all_targets = []
        for line in content.splitlines():
            item = parse_ip_port_country_line(line, self.port_input.value())
            if item:
                self.all_targets.append(item)

        if not self.all_targets:
            QMessageBox.warning(self, "提示", "远程TXT中没有解析到可用目标。")
            self.set_status("远程TXT无可用内容")
            return

        self.build_country_checkboxes()
        self.append_log(f"远程TXT加载完成，共解析到 {len(self.all_targets)} 个目标。")
        self.set_status("已加载远程TXT")

    def build_country_checkboxes(self):
        while self.country_layout.count():
            child = self.country_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        self.country_checkboxes = {}
        stat = defaultdict(int)
        for item in self.all_targets:
            country = item.get("country", "UNKNOWN").upper()
            stat[country] += 1

        countries = sorted(stat.keys())
        cols = 5
        for idx, country in enumerate(countries):
            checkbox = QCheckBox(f"{country} ({stat[country]})")
            checkbox.setChecked(True)
            self.country_checkboxes[country] = checkbox
            row = idx // cols
            col = idx % cols
            self.country_layout.addWidget(checkbox, row, col)

        self.append_log("已按国家分组：")
        for country in countries:
            self.append_log(f"  {country}: {stat[country]} 条")

    def filter_country_checkboxes(self):
        keyword = self.country_search_edit.text().strip().upper()
        for country, checkbox in self.country_checkboxes.items():
            if not keyword or keyword in country.upper():
                checkbox.show()
            else:
                checkbox.hide()

    def get_selected_countries(self):
        return [country for country, cb in self.country_checkboxes.items() if cb.isChecked()]

    def get_selected_targets(self):
        selected = set(self.get_selected_countries())
        if not selected:
            return []
        return [item for item in self.all_targets if item.get("country", "UNKNOWN").upper() in selected]

    def select_all_countries(self):
        for cb in self.country_checkboxes.values():
            cb.setChecked(True)

    def unselect_all_countries(self):
        for cb in self.country_checkboxes.values():
            cb.setChecked(False)

    def start_latency_test(self):
        if not self.all_targets:
            QMessageBox.warning(self, "提示", "请先导入本地TXT或远程TXT链接。")
            return

        selected_targets = self.get_selected_targets()
        if not selected_targets:
            QMessageBox.warning(self, "提示", "请至少勾选一个国家进行测试。")
            return

        self.latency_results = []
        self.results = []
        self.log_edit.clear()
        self.reset_progress()

        threads = self.thread_input.value()
        self.worker = LatencyTestWorker(selected_targets, threads)
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished_signal.connect(self.on_latency_finished)
        self.worker.start()

        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)
        self.set_status("延迟测试中")

        selected_countries = ", ".join(self.get_selected_countries())
        self.append_log(f"开始延迟测试，已勾选国家：{selected_countries}")

    def on_latency_finished(self, results):
        self.latency_results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True if results else False)
        self.set_status("延迟测试完成")
        self.append_log(f"延迟测试完成，保留 {len(results)} 个有延迟节点。")

    def start_speed_test(self):
        if not self.latency_results:
            QMessageBox.warning(self, "提示", "请先进行延迟测试，且必须有可用节点。")
            return

        self.results = []
        self.reset_progress()

        threads = self.thread_input.value()
        self.worker = SpeedTestWorker(self.latency_results, threads)
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished_signal.connect(self.on_speed_finished)
        self.worker.start()

        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)
        self.set_status("测速中")
        self.append_log("开始测速（仅针对有延迟节点）...")

    def on_speed_finished(self, results):
        self.results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True)
        self.set_status("测速完成")
        self.append_log(f"测速完成，共得到 {len(results)} 条结果。")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("正在停止任务...")
            self.set_status("停止中")

    def clear_results(self):
        self.latency_results = []
        self.results = []
        self.log_edit.clear()
        self.reset_progress()
        self.set_status("空闲")

    def prepare_export_items(self):
        data_to_export = self.results if self.results else self.latency_results
        if not data_to_export:
            return None, "没有可导出的结果。"

        countries = split_countries(self.country_input.text())
        topn_each = self.topn_input.value()

        grouped = defaultdict(list)
        for item in data_to_export:
            country = item.get("country", "UNKNOWN").upper()
            if countries and country not in countries:
                continue
            grouped[country].append(item)

        export_items = []
        target_countries = countries if countries else sorted(grouped.keys())
        for country in target_countries:
            items = grouped.get(country, [])
            items.sort(key=lambda x: x.get("download_speed", 0), reverse=True)
            if topn_each > 0:
                items = items[:topn_each]
            export_items.extend(items)

        if not export_items:
            return None, "没有符合筛选条件的结果。"

        return export_items, None

    def export_results_local(self):
        export_items, err = self.prepare_export_items()
        if err:
            QMessageBox.warning(self, "提示", err)
            return

        filename = ensure_txt_filename(self.export_name_edit.text())
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存结果",
            filename,
            "Text Files (*.txt)"
        )
        if not save_path:
            return

        content = build_export_text(export_items)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(content)

        self.append_log(f"已导出 {len(export_items)} 条结果到本地：{save_path}")
        QMessageBox.information(self, "完成", f"已导出到本地：\n{save_path}")

    def export_results_webdav(self):
        export_items, err = self.prepare_export_items()
        if err:
            QMessageBox.warning(self, "提示", err)
            return

        base_url = self.webdav_url_edit.text().strip()
        username = self.webdav_user_edit.text().strip()
        password = self.webdav_pass_edit.text()
        remote_dir = self.webdav_dir_edit.text().strip()
        filename = ensure_txt_filename(self.export_name_edit.text())

        if not base_url:
            QMessageBox.warning(self, "提示", "请输入WebDAV地址。")
            return
        if not username:
            QMessageBox.warning(self, "提示", "请输入WebDAV用户名。")
            return

        try:
            content = build_export_text(export_items).encode("utf-8")
            status, full_url = upload_to_webdav(
                base_url=base_url,
                remote_dir=remote_dir,
                filename=filename,
                content=content,
                username=username,
                password=password
            )
            self.append_log(f"已导出 {len(export_items)} 条结果到WebDAV：{full_url} (HTTP {status})")
            QMessageBox.information(self, "完成", f"已成功上传到 WebDAV：\n{full_url}")
        except Exception as e:
            self.append_log(f"导出到WebDAV失败：{e}")
            QMessageBox.warning(self, "失败", f"导出到WebDAV失败：\n{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
