import sys
import os
import time
import socket
import ssl
import ipaddress
import threading
import re
from urllib.parse import urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QScrollArea, QGridLayout,
    QProgressBar, QGroupBox, QFrame
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
            host, port = line.rsplit(":", 1)
            host = host.strip()
            port = int(port.strip())

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


def download_speed_test(ip: str, port: int, country: str, latency: float, stop_event: threading.Event):
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

    return {
        "ip": ip,
        "port": port,
        "country": country,
        "latency": latency,
        "download_speed": speed,
    }


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
            return {
                "ip": item["ip"],
                "port": item["port"],
                "country": item["country"],
                "latency": latency,
                "download_speed": 0.0,
            }

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
                        self.result_signal.emit(result)
                        self.log.emit(
                            f"[{completed}/{len(self.targets)}] "
                            f"{format_ip_port(result['ip'], result['port'])} | "
                            f"{result['country']} | "
                            f"{result['latency']:.2f} ms"
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
            self.log.emit("没有可测速的节点，请先进行延迟测试。")
            self.finished_signal.emit([])
            return

        self.log.emit(f"开始对 {len(self.targets)} 个有延迟节点进行测速...")
        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(
                    download_speed_test,
                    item["ip"],
                    item["port"],
                    item["country"],
                    item["latency"],
                    self.stop_event
                ): item
                for item in self.targets
            }

            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    self.log.emit("测速已停止。")
                    break

                completed += 1
                self.progress.emit(completed, len(self.targets))

                try:
                    result = future.result()
                    results.append(result)
                    self.result_signal.emit(result)
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
        self.setWindowTitle("国家分组测速工具 - 增强版")
        self.resize(1380, 920)

        self.file_path = ""
        self.all_targets = []
        self.country_checkboxes = {}
        self.latency_results = []
        self.results = []
        self.worker = None

        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("国家分组测速工具")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # 文件区域
        file_group = QGroupBox("文件与参数")
        file_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("请选择TXT文件...")
        btn_browse = QPushButton("选择文件")
        btn_browse.clicked.connect(self.choose_file)
        row1.addWidget(QLabel("TXT文件:"))
        row1.addWidget(self.file_edit)
        row1.addWidget(btn_browse)
        file_layout.addLayout(row1)

        row2 = QHBoxLayout()
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

        row2.addWidget(QLabel("默认端口:"))
        row2.addWidget(self.port_input)
        row2.addSpacing(12)

        row2.addWidget(QLabel("线程数:"))
        row2.addWidget(self.thread_input)
        row2.addSpacing(12)

        row2.addWidget(QLabel("导出筛选国家:"))
        row2.addWidget(self.country_input)
        row2.addSpacing(12)

        row2.addWidget(QLabel("每国前N条:"))
        row2.addWidget(self.topn_input)
        file_layout.addLayout(row2)

        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # 国家分组区域
        country_group = QGroupBox("国家分组选择")
        country_layout_main = QVBoxLayout()

        country_top = QHBoxLayout()
        country_top.addWidget(QLabel("勾选要测试的国家："))

        self.btn_select_all_country = QPushButton("全选")
        self.btn_unselect_all_country = QPushButton("全不选")
        self.btn_select_all_country.clicked.connect(self.select_all_countries)
        self.btn_unselect_all_country.clicked.connect(self.unselect_all_countries)

        country_top.addWidget(self.btn_select_all_country)
        country_top.addWidget(self.btn_unselect_all_country)
        country_top.addStretch()
        country_layout_main.addLayout(country_top)

        self.country_scroll = QScrollArea()
        self.country_scroll.setWidgetResizable(True)
        self.country_scroll.setFixedHeight(140)

        self.country_widget = QWidget()
        self.country_layout = QGridLayout()
        self.country_layout.setSpacing(10)
        self.country_widget.setLayout(self.country_layout)

        self.country_scroll.setWidget(self.country_widget)
        country_layout_main.addWidget(self.country_scroll)

        country_group.setLayout(country_layout_main)
        main_layout.addWidget(country_group)

        # 操作区域
        action_group = QGroupBox("操作")
        action_layout = QVBoxLayout()

        row3 = QHBoxLayout()
        self.btn_latency = QPushButton("延迟测试")
        self.btn_speed = QPushButton("测速")
        self.btn_stop = QPushButton("停止")
        self.btn_export = QPushButton("导出结果")
        self.btn_clear = QPushButton("清空结果")

        self.btn_latency.clicked.connect(self.start_latency_test)
        self.btn_speed.clicked.connect(self.start_speed_test)
        self.btn_stop.clicked.connect(self.stop_test)
        self.btn_export.clicked.connect(self.export_results)
        self.btn_clear.clicked.connect(self.clear_results)

        self.btn_speed.setEnabled(False)

        row3.addWidget(self.btn_latency)
        row3.addWidget(self.btn_speed)
        row3.addWidget(self.btn_stop)
        row3.addWidget(self.btn_export)
        row3.addWidget(self.btn_clear)
        row3.addStretch()
        action_layout.addLayout(row3)

        # 进度条区域
        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_label = QLabel("进度：0/0")
        progress_row.addWidget(self.progress_bar)
        progress_row.addWidget(self.progress_label)
        action_layout.addLayout(progress_row)

        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # 结果区域
        result_group = QGroupBox("测试结果")
        result_layout = QVBoxLayout()

        # 国家统计表
        result_layout.addWidget(QLabel("国家分组统计："))
        self.country_table = QTableWidget(0, 4)
        self.country_table.setHorizontalHeaderLabels(["国家", "数量", "平均延迟(ms)", "平均速度(MB/s)"])
        self.country_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.country_table.setSortingEnabled(True)
        self.country_table.setMinimumHeight(220)
        result_layout.addWidget(self.country_table)

        # 明细表
        result_layout.addWidget(QLabel("节点明细："))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "端口", "国家代码", "延迟(ms)", "速度(MB/s)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        result_layout.addWidget(self.table)

        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)

        # 日志区域
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
            QLineEdit, QSpinBox, QTextEdit, QTableWidget {
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
            QHeaderView::section {
                background-color: #323546;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #44485a;
                font-weight: bold;
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
        """)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择TXT文件", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.file_path = path
            self.file_edit.setText(path)
            self.log_edit.clear()
            if self.load_targets_and_group_countries():
                self.append_log(f"文件加载完成，共解析到 {len(self.all_targets)} 个目标。")
                self.update_country_stats(self.all_targets)

    def load_targets_and_group_countries(self):
        file_path = self.file_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "提示", "请先选择TXT文件。")
            return False

        if not os.path.exists(file_path):
            QMessageBox.warning(self, "提示", "文件不存在。")
            return False

        self.all_targets = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                item = parse_ip_port_country_line(line, self.port_input.value())
                if item:
                    self.all_targets.append(item)

        if not self.all_targets:
            QMessageBox.warning(self, "提示", "没有解析到可用目标。")
            return False

        self.build_country_checkboxes()
        return True

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

    def get_selected_countries(self):
        return [country for country, cb in self.country_checkboxes.items() if cb.isChecked()]

    def get_selected_targets(self):
        selected_countries = set(self.get_selected_countries())
        if not selected_countries:
            return []
        return [
            item for item in self.all_targets
            if item.get("country", "UNKNOWN").upper() in selected_countries
        ]

    def select_all_countries(self):
        for checkbox in self.country_checkboxes.values():
            checkbox.setChecked(True)

    def unselect_all_countries(self):
        for checkbox in self.country_checkboxes.values():
            checkbox.setChecked(False)

    def append_log(self, text):
        self.log_edit.append(text)

    def update_progress(self, current, total):
        self.progress_bar.setMaximum(total if total > 0 else 1)
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"进度：{current}/{total}")

    def reset_progress(self):
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        self.progress_label.setText("进度：0/0")

    def add_result_row(self, item):
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(item["ip"]))
        self.table.setItem(row, 1, QTableWidgetItem(str(item["port"])))
        self.table.setItem(row, 2, QTableWidgetItem(item.get("country", "UNKNOWN")))
        self.table.setItem(row, 3, QTableWidgetItem(f"{item.get('latency', 0):.2f}"))

        speed = item.get("download_speed", 0.0)
        self.table.setItem(row, 4, QTableWidgetItem("" if speed == 0 else f"{speed:.2f}"))

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
            self.country_table.setItem(row, 1, QTableWidgetItem(str(count)))
            self.country_table.setItem(row, 2, QTableWidgetItem(f"{avg_latency:.2f}"))
            self.country_table.setItem(row, 3, QTableWidgetItem(f"{avg_speed:.2f}"))

    def start_latency_test(self):
        if not self.all_targets:
            ok = self.load_targets_and_group_countries()
            if not ok:
                return

        selected_targets = self.get_selected_targets()
        if not selected_targets:
            QMessageBox.warning(self, "提示", "请至少勾选一个国家进行测试。")
            return

        self.latency_results = []
        self.results = []
        self.table.setRowCount(0)
        self.country_table.setRowCount(0)
        self.log_edit.clear()
        self.reset_progress()

        threads = self.thread_input.value()

        self.worker = LatencyTestWorker(selected_targets, threads)
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.result_signal.connect(self.on_latency_result)
        self.worker.finished_signal.connect(self.on_latency_finished)
        self.worker.start()

        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)

        selected_countries = ", ".join(self.get_selected_countries())
        self.append_log(f"开始延迟测试，已勾选国家：{selected_countries}")

    def on_latency_result(self, item):
        self.latency_results.append(item)
        self.add_result_row(item)
        self.update_country_stats(self.latency_results)

    def on_latency_finished(self, results):
        self.latency_results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True if results else False)
        self.update_country_stats(results)
        self.append_log(f"延迟测试完成，保留 {len(results)} 个有延迟节点。")

    def start_speed_test(self):
        if not self.latency_results:
            QMessageBox.warning(self, "提示", "请先进行延迟测试，且必须有可用节点。")
            return

        self.results = []
        self.table.setRowCount(0)
        self.reset_progress()

        threads = self.thread_input.value()

        self.worker = SpeedTestWorker(self.latency_results, threads)
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.result_signal.connect(self.on_speed_result)
        self.worker.finished_signal.connect(self.on_speed_finished)
        self.worker.start()

        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)
        self.append_log("开始测速（仅针对有延迟节点）...")

    def on_speed_result(self, item):
        self.results.append(item)
        self.add_result_row(item)
        self.update_country_stats(self.results)

    def on_speed_finished(self, results):
        self.results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True)
        self.update_country_stats(results)
        self.append_log(f"测速完成，共得到 {len(results)} 条结果。")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("正在停止任务...")

    def clear_results(self):
        self.latency_results = []
        self.results = []
        self.table.setRowCount(0)
        self.country_table.setRowCount(0)
        self.log_edit.clear()
        self.reset_progress()

    def export_results(self):
        data_to_export = self.results if self.results else self.latency_results
        if not data_to_export:
            QMessageBox.warning(self, "提示", "没有可导出的结果。")
            return

        countries = split_countries(self.country_input.text())
        topn_each = self.topn_input.value()

        export_items = export_grouped_by_country(data_to_export, countries, topn_each)

        if not export_items:
            QMessageBox.warning(self, "提示", "没有符合筛选条件的结果。")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存结果",
            "country_speed_result.txt",
            "Text Files (*.txt)"
        )
        if not save_path:
            return

        grouped = defaultdict(list)
        for item in export_items:
            grouped[item["country"]].append(item)

        with open(save_path, "w", encoding="utf-8") as f:
            for country in grouped:
                f.write(f"===== {country} =====\n")
                for item in grouped[country]:
                    ip_port = format_ip_port(item["ip"], item["port"])
                    speed = item.get("download_speed", 0.0)
                    if speed > 0:
                        line = f"{ip_port}#{item['country']}+{speed:.2f}MB/s"
                    else:
                        line = f"{ip_port}#{item['country']}+{item['latency']:.2f}ms"
                    f.write(line + "\n")
                f.write("\n")

        QMessageBox.information(self, "完成", f"已导出 {len(export_items)} 条结果到：\n{save_path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
