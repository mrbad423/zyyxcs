import sys
import os
import time
import socket
import ssl
import ipaddress
import threading
import re
import tempfile
from urllib.parse import urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtGui import QColor, QFont, QClipboard
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QScrollArea, QGridLayout,
    QProgressBar, QGroupBox, QFrame, QStatusBar, QInputDialog
)

TEST_HOST = "speed.cloudflare.com"
DOWNLOAD_PATH = "/__down?bytes=50000000"
TEMP_FILE = "downloaded_targets.txt"


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
    country_candidates = {"HK", "JP", "SG", "TW", "US", "KR", "DE", "FR", "GB", "UK", "NL", "CA", "AU", "IN", "RU", "BR", "IT", "ES", "VN", "TH", "MY", "PH", "ID", "MO"}
    parts = re.split(r'[^A-Z]+', text_up)
    for part in parts:
        if part in country_candidates:
            return part
    m = re.search(r'(?:COUNTRY|LOC|REGION|CODE)=([A-Z]{2})\b', text_up)
    if m and m.group(1) in country_candidates:
        return m.group(1)
    return "UNKNOWN"


def parse_ip_port_country_line(line: str, default_port: int = 443):
    line = line.strip()
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

    # URL 处理
    if "://" in line:
        try:
            parsed = urlparse(line)
            host = parsed.hostname
            port = parsed.port or default_port
            if not host:
                return None
            try:
                ipaddress.ip_address(host)
                return {"ip": host, "port": port, "country": country}
            except Exception:
                ip = socket.gethostbyname(host)
                return {"ip": ip, "port": port, "country": country}
        except Exception:
            return None

    # IPv6
    if line.startswith("[") and "]" in line:
        try:
            host_part, rest = line.split("]", 1)
            ip = host_part[1:].strip()
            port = default_port
            if rest.startswith(":"):
                port = int(rest[1:].strip())
            ipaddress.ip_address(ip)
            return {"ip": ip, "port": port, "country": country}
        except Exception:
            return None

    try:
        ipaddress.ip_address(line)
        return {"ip": line, "port": default_port, "country": country}
    except Exception:
        pass

    if ":" in line:
        try:
            host, port_str = line.rsplit(":", 1)
            host = host.strip()
            port = int(port_str.strip())
            try:
                ipaddress.ip_address(host)
                return {"ip": host, "port": port, "country": country}
            except Exception:
                ip = socket.gethostbyname(host)
                return {"ip": ip, "port": port, "country": country}
        except Exception:
            return None

    try:
        ip = socket.gethostbyname(line)
        return {"ip": ip, "port": default_port, "country": country}
    except Exception:
        return None


def tcp_ping(ip: str, port: int, timeout=1.5):
    start = time.time()
    try:
        if ":" in ip:
            addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
            family, socktype, proto, _, sockaddr = addrinfo[0]
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None


def download_speed_test(ip: str, port: int, country: str, latency: float, stop_event: threading.Event):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = (f"GET {DOWNLOAD_PATH} HTTP/1.1\r\nHost: {TEST_HOST}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
    speed = 0.0
    try:
        if ":" in ip:
            addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
            family, socktype, proto, _, sockaddr = addrinfo[0]
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
    return {"ip": ip, "port": port, "country": country, "latency": latency, "download_speed": speed}


def export_grouped_by_country(results, countries, topn_each):
    grouped = defaultdict(list)
    for item in results:
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
    return export_items


class DownloadWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    finished_signal = pyqtSignal(str)  # 返回下载后的本地文件路径

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            self.log.emit(f"开始下载: {self.url}")
            response = requests.get(self.url, stream=True, timeout=30)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            with open(TEMP_FILE, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = int((downloaded / total_size) * 100)
                            self.progress.emit(percent, 100)
            self.log.emit(f"下载完成，已保存到 {TEMP_FILE}")
            self.finished_signal.emit(TEMP_FILE)
        except Exception as e:
            self.log.emit(f"下载失败: {e}")
            self.finished_signal.emit("")


class LatencyTestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    result_signal = pyqtSignal(dict)
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
            self.finished_signal.emit([])
            return
        self.log.emit(f"开始延迟测试 {len(self.targets)} 个目标...")
        results = []
        completed = 0
        def ping_one(item):
            latency = tcp_ping(item["ip"], item["port"], timeout=1.5)
            if latency is None:
                return None
            return {"ip": item["ip"], "port": item["port"], "country": item["country"], "latency": latency, "download_speed": 0.0}
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(ping_one, item): item for item in self.targets}
            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    break
                completed += 1
                self.progress.emit(completed, len(self.targets))
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.result_signal.emit(result)
                except Exception:
                    pass
        results.sort(key=lambda x: x["latency"])
        self.finished_signal.emit(results)


class SpeedTestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    result_signal = pyqtSignal(dict)
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
            self.finished_signal.emit([])
            return
        self.log.emit(f"开始测速 {len(self.targets)} 个节点...")
        results = []
        completed = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(download_speed_test, item["ip"], item["port"], item["country"], item["latency"], self.stop_event): item for item in self.targets}
            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    break
                completed += 1
                self.progress.emit(completed, len(self.targets))
                try:
                    result = future.result()
                    results.append(result)
                    self.result_signal.emit(result)
                except Exception:
                    pass
        results.sort(key=lambda x: x["download_speed"], reverse=True)
        self.finished_signal.emit(results)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CF 国家分组测速工具 - 高级增强版")
        self.resize(1420, 980)
        self.all_targets = []
        self.country_checkboxes = {}
        self.latency_results = []
        self.results = []
        self.worker = None
        self.download_worker = None
        self.init_ui()
        self.apply_styles()
        self.statusBar().showMessage("就绪 - 支持本地TXT或URL导入（如 https://zip.cm.edu.kg/all.txt）")

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("CF 国家分组测速工具 - 高级增强版")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # 文件与导入区域
        file_group = QGroupBox("文件导入")
        file_layout = QVBoxLayout()
        row_file = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("本地TXT路径 或 URL（如 https://zip.cm.edu.kg/all.txt）")
        btn_browse = QPushButton("选择本地文件")
        btn_url = QPushButton("从URL导入")
        btn_browse.clicked.connect(self.choose_local_file)
        btn_url.clicked.connect(self.import_from_url)
        row_file.addWidget(QLabel("文件/URL:"))
        row_file.addWidget(self.file_edit)
        row_file.addWidget(btn_browse)
        row_file.addWidget(btn_url)
        file_layout.addLayout(row_file)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # 参数设置
        param_group = QGroupBox("参数设置")
        param_layout = QHBoxLayout()
        self.port_input = QSpinBox(); self.port_input.setRange(1, 65535); self.port_input.setValue(443)
        self.thread_input = QSpinBox(); self.thread_input.setRange(1, 500); self.thread_input.setValue(20)
        self.country_input = QLineEdit(); self.country_input.setPlaceholderText("导出筛选国家，留空=全部")
        self.topn_input = QSpinBox(); self.topn_input.setRange(0, 100000); self.topn_input.setValue(10)
        param_layout.addWidget(QLabel("默认端口:")); param_layout.addWidget(self.port_input)
        param_layout.addWidget(QLabel("线程数:")); param_layout.addWidget(self.thread_input)
        param_layout.addWidget(QLabel("导出筛选:")); param_layout.addWidget(self.country_input)
        param_layout.addWidget(QLabel("每国前N条:")); param_layout.addWidget(self.topn_input)
        param_group.setLayout(param_layout)
        main_layout.addWidget(param_group)

        # 国家分组
        country_group = QGroupBox("国家分组选择（勾选要测试的国家）")
        country_main = QVBoxLayout()
        country_top = QHBoxLayout()
        country_top.addWidget(QLabel("国家列表:"))
        self.btn_select_all = QPushButton("全选")
        self.btn_unselect_all = QPushButton("全不选")
        self.btn_select_all.clicked.connect(self.select_all_countries)
        self.btn_unselect_all.clicked.connect(self.unselect_all_countries)
        country_top.addWidget(self.btn_select_all)
        country_top.addWidget(self.btn_unselect_all)
        country_top.addStretch()
        country_main.addLayout(country_top)
        self.country_scroll = QScrollArea(); self.country_scroll.setWidgetResizable(True); self.country_scroll.setFixedHeight(150)
        self.country_widget = QWidget(); self.country_layout = QGridLayout(); self.country_widget.setLayout(self.country_layout)
        self.country_scroll.setWidget(self.country_widget)
        country_main.addWidget(self.country_scroll)
        country_group.setLayout(country_main)
        main_layout.addWidget(country_group)

        # 操作按钮 + 进度
        action_group = QGroupBox("操作")
        action_layout = QVBoxLayout()
        btn_row = QHBoxLayout()
        self.btn_latency = QPushButton("延迟测试")
        self.btn_speed = QPushButton("测速")
        self.btn_stop = QPushButton("停止")
        self.btn_export = QPushButton("导出结果")
        self.btn_clear = QPushButton("清空")
        self.btn_latency.clicked.connect(self.start_latency_test)
        self.btn_speed.clicked.connect(self.start_speed_test)
        self.btn_stop.clicked.connect(self.stop_test)
        self.btn_export.clicked.connect(self.export_results)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_speed.setEnabled(False)
        btn_row.addWidget(self.btn_latency)
        btn_row.addWidget(self.btn_speed)
        btn_row.addWidget(self.btn_stop)
        btn_row.addWidget(self.btn_export)
        btn_row.addWidget(self.btn_clear)
        action_layout.addLayout(btn_row)
        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("进度: 0/0")
        progress_row.addWidget(self.progress_bar)
        progress_row.addWidget(self.progress_label)
        action_layout.addLayout(progress_row)
        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # 国家统计表
        stat_group = QGroupBox("国家分组统计")
        stat_layout = QVBoxLayout()
        self.country_table = QTableWidget(0, 4)
        self.country_table.setHorizontalHeaderLabels(["国家", "数量", "平均延迟(ms)", "平均速度(MB/s)"])
        self.country_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.country_table.setSortingEnabled(True)
        self.country_table.cellDoubleClicked.connect(self.on_country_table_double_click)
        stat_layout.addWidget(self.country_table)
        stat_group.setLayout(stat_layout)
        main_layout.addWidget(stat_group)

        # 节点明细表
        detail_group = QGroupBox("节点明细（双击行可复制）")
        detail_layout = QVBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "端口", "国家", "延迟(ms)", "速度(MB/s)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self.table.cellDoubleClicked.connect(self.on_table_double_click)
        detail_layout.addWidget(self.table)
        detail_group.setLayout(detail_layout)
        main_layout.addWidget(detail_group)

        # 日志
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        self.setLayout(main_layout)
        self.statusBar = QStatusBar()
        main_layout.addWidget(self.statusBar)  # 状态栏

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget { background-color: #1e1f26; color: #e8e8e8; font-size: 13px; }
            QGroupBox { border: 1px solid #3a3d4a; border-radius: 10px; margin-top: 12px; padding-top: 14px; background-color: #252733; }
            QGroupBox::title { color: #7cc7ff; }
            QLabel { font-weight: bold; }
            QLineEdit, QSpinBox, QTextEdit, QTableWidget { background-color: #2b2d3a; border: 1px solid #44485a; border-radius: 8px; padding: 6px; }
            QPushButton { background-color: #3d7eff; border: none; border-radius: 8px; padding: 8px 18px; color: white; font-weight: bold; }
            QPushButton:hover { background-color: #5a92ff; }
            QPushButton:pressed { background-color: #2f66d0; }
            QHeaderView::section { background-color: #323546; padding: 6px; }
            QProgressBar::chunk { background-color: #00c853; }
            QStatusBar { background-color: #252733; }
        """)

    def choose_local_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择TXT文件", "", "Text Files (*.txt)")
        if path:
            self.file_edit.setText(path)
            self.load_and_process_file(path)

    def import_from_url(self):
        url, ok = QInputDialog.getText(self, "从URL导入", "请输入TXT链接（如 https://zip.cm.edu.kg/all.txt）:", QLineEdit.Normal, "https://zip.cm.edu.kg/all.txt")
        if ok and url.strip():
            self.file_edit.setText(url.strip())
            self.download_worker = DownloadWorker(url.strip())
            self.download_worker.log.connect(self.append_log)
            self.download_worker.progress.connect(self.update_download_progress)
            self.download_worker.finished_signal.connect(self.on_download_finished)
            self.download_worker.start()
            self.btn_latency.setEnabled(False)

    def update_download_progress(self, value, total):
        self.progress_bar.setValue(value)

    def on_download_finished(self, local_path):
        self.btn_latency.setEnabled(True)
        if local_path and os.path.exists(local_path):
            self.load_and_process_file(local_path)
        else:
            QMessageBox.warning(self, "下载失败", "无法下载或保存文件，请检查网络或URL。")

    def load_and_process_file(self, path):
        self.all_targets = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    item = parse_ip_port_country_line(line, self.port_input.value())
                    if item:
                        self.all_targets.append(item)
            if not self.all_targets:
                QMessageBox.warning(self, "提示", "未解析到有效节点。")
                return
            self.build_country_checkboxes()
            self.update_country_stats(self.all_targets)
            self.append_log(f"加载完成，共 {len(self.all_targets)} 个节点（来源: {path}）")
            self.statusBar.showMessage(f"已加载 {len(self.all_targets)} 个节点")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载失败: {e}")

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
            cb = QCheckBox(f"{country} ({stat[country]})")
            cb.setChecked(True)
            self.country_checkboxes[country] = cb
            self.country_layout.addWidget(cb, idx // cols, idx % cols)
        self.append_log("国家分组已生成")

    def get_selected_countries(self):
        return [c for c, cb in self.country_checkboxes.items() if cb.isChecked()]

    def get_selected_targets(self):
        sel = set(self.get_selected_countries())
        return [item for item in self.all_targets if item.get("country", "UNKNOWN").upper() in sel]

    def select_all_countries(self):
        for cb in self.country_checkboxes.values():
            cb.setChecked(True)

    def unselect_all_countries(self):
        for cb in self.country_checkboxes.values():
            cb.setChecked(False)

    def append_log(self, text):
        self.log_edit.append(text)

    def update_progress(self, current, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"进度: {current}/{total}")

    def reset_progress(self):
        self.progress_bar.setValue(0)
        self.progress_label.setText("进度: 0/0")

    def add_result_row(self, item):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(item["ip"]))
        self.table.setItem(row, 1, QTableWidgetItem(str(item["port"])))
        self.table.setItem(row, 2, QTableWidgetItem(item.get("country", "UNKNOWN")))
        self.table.setItem(row, 3, NumericTableWidgetItem(item.get("latency", 0)))
        self.table.setItem(row, 4, NumericTableWidgetItem(item.get("download_speed", 0)))

    def update_country_stats(self, items):
        grouped = defaultdict(list)
        for item in items:
            grouped[item.get("country", "UNKNOWN").upper()].append(item)
        self.country_table.setRowCount(0)
        for country in sorted(grouped.keys()):
            group_items = grouped[country]
            count = len(group_items)
            latencies = [x.get("latency", 0) for x in group_items if x.get("latency", 0) > 0]
            speeds = [x.get("download_speed", 0) for x in group_items if x.get("download_speed", 0) > 0]
            avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
            avg_speed = round(sum(speeds) / len(speeds), 2) if speeds else 0.0
            row = self.country_table.rowCount()
            self.country_table.insertRow(row)
            self.country_table.setItem(row, 0, QTableWidgetItem(country))
            self.country_table.setItem(row, 1, NumericTableWidgetItem(count))
            self.country_table.setItem(row, 2, NumericTableWidgetItem(avg_latency))
            self.country_table.setItem(row, 3, NumericTableWidgetItem(avg_speed))

    def start_latency_test(self):
        if not self.all_targets:
            path = self.file_edit.text().strip()
            if path and (path.startswith("http") or os.path.exists(path)):
                self.load_and_process_file(path if not path.startswith("http") else TEMP_FILE)
            if not self.all_targets:
                QMessageBox.warning(self, "提示", "请先导入文件或URL。")
                return
        selected = self.get_selected_targets()
        if not selected:
            QMessageBox.warning(self, "提示", "请至少勾选一个国家。")
            return
        self.latency_results = []
        self.results = []
        self.table.setRowCount(0)
        self.country_table.setRowCount(0)
        self.log_edit.clear()
        self.reset_progress()
        self.worker = LatencyTestWorker(selected, self.thread_input.value())
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.result_signal.connect(lambda item: (self.latency_results.append(item), self.add_result_row(item), self.update_country_stats(self.latency_results)))
        self.worker.finished_signal.connect(self.on_latency_finished)
        self.worker.start()
        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)

    def on_latency_finished(self, results):
        self.latency_results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(bool(results))
        self.update_country_stats(results)
        self.append_log(f"延迟测试完成，保留 {len(results)} 个有效节点。")

    def start_speed_test(self):
        if not self.latency_results:
            QMessageBox.warning(self, "提示", "请先完成延迟测试。")
            return
        self.results = []
        self.table.setRowCount(0)
        self.reset_progress()
        self.worker = SpeedTestWorker(self.latency_results, self.thread_input.value())
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.result_signal.connect(lambda item: (self.results.append(item), self.add_result_row(item), self.update_country_stats(self.results)))
        self.worker.finished_signal.connect(self.on_speed_finished)
        self.worker.start()
        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)

    def on_speed_finished(self, results):
        self.results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True)
        self.update_country_stats(results)
        self.append_log(f"测速完成，共 {len(results)} 条结果。")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("任务已停止。")

    def clear_results(self):
        self.latency_results.clear()
        self.results.clear()
        self.table.setRowCount(0)
        self.country_table.setRowCount(0)
        self.log_edit.clear()
        self.reset_progress()

    def export_results(self):
        data = self.results if self.results else self.latency_results
        if not data:
            QMessageBox.warning(self, "提示", "没有结果可导出。")
            return
        countries = split_countries(self.country_input.text())
        topn = self.topn_input.value()
        export_items = export_grouped_by_country(data, countries, topn)
        if not export_items:
            QMessageBox.warning(self, "提示", "没有符合条件的导出项。")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "导出结果", "result.txt", "Text Files (*.txt)")
        if not save_path:
            return
        grouped = defaultdict(list)
        for item in export_items:
            grouped[item["country"]].append(item)
        with open(save_path, "w", encoding="utf-8") as f:
            for country in sorted(grouped.keys()):
                f.write(f"===== {country} =====\n")
                for item in sorted(grouped[country], key=lambda x: x.get("download_speed", 0), reverse=True):
                    ip_port = format_ip_port(item["ip"], item["port"])
                    speed = item.get("download_speed", 0)
                    if speed > 0:
                        f.write(f"{ip_port}#{item['country']}+{speed:.2f}MB/s\n")
                    else:
                        f.write(f"{ip_port}#{item['country']}+{item.get('latency', 0):.2f}ms\n")
                f.write("\n")
        QMessageBox.information(self, "完成", f"已导出 {len(export_items)} 条结果到\n{save_path}")

    def on_table_double_click(self, row, col):
        ip = self.table.item(row, 0).text()
        port = self.table.item(row, 1).text()
        country = self.table.item(row, 2).text()
        text = f"{ip}:{port}#{country}"
        QApplication.clipboard().setText(text)
        self.statusBar.showMessage(f"已复制: {text}")

    def on_country_table_double_click(self, row, col):
        country = self.country_table.item(row, 0).text()
        for c, cb in self.country_checkboxes.items():
            cb.setChecked(c == country)
        self.append_log(f"已仅勾选国家: {country}")

class NumericTableWidgetItem(QTableWidgetItem):
    def __init__(self, value):
        super().__init__(f"{value:.2f}" if isinstance(value, float) else str(value))
        self.setData(Qt.UserRole, float(value) if isinstance(value, (int, float)) else 0)

    def __lt__(self, other):
        return self.data(Qt.UserRole) < other.data(Qt.UserRole)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
