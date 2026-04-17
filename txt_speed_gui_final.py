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

# Try to import requests, if not found, prompt user to install
try:
    import requests
except ImportError:
    print("错误：缺少 'requests' 库。请运行 'pip install requests' 来安装。")
    sys.exit(1)


from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QScrollArea, QGridLayout,
    QProgressBar, QGroupBox, QStatusBar, QMainWindow
)

TEST_HOST = "speed.cloudflare.com"
DOWNLOAD_PATH = "/__down?bytes=50000000"


# --- Helper Classes and Functions ---

class NumericTableWidgetItem(QTableWidgetItem):
    """ Custom QTableWidgetItem for numerical sorting. """
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)


def format_ip_port(ip: str, port: int) -> str:
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def split_countries(country_text: str):
    if not country_text.strip():
        return []
    parts = country_text.replace("，", ",").split(",")
    return [p.strip().upper() for p in parts if p.strip()]


def extract_country_code(text: str):
    if not text:
        return "UNKNOWN"
    text_up = text.upper().strip()
    m = re.search(r'#([A-Z]{2})\b', text_up)
    if m:
        return m.group(1)
    country_candidates = {"HK", "JP", "SG", "TW", "US", "KR", "DE", "FR", "GB", "UK", "NL", "CA", "AU"}
    parts = re.split(r'[^A-Z]+', text_up)
    for part in parts:
        if part in country_candidates:
            return part
    return "UNKNOWN"


def parse_ip_port_country_line(line: str, default_port: int = 443):
    line = line.strip()
    if not line:
        return None
    country = extract_country_code(line)
    
    # Simple parsing logic
    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if "://" in line:
        try:
            parsed = urlparse(line)
            host, port = parsed.hostname, parsed.port or default_port
        except Exception: return None
    elif line.startswith("[") and "]" in line:
        try:
            host, port_str = line[1:].split("]:")
            port = int(port_str)
        except Exception: host, port = line, default_port
    elif ":" in line and line.count(':') == 1:
        try:
            host, port_str = line.rsplit(":", 1)
            port = int(port_str)
        except Exception: host, port = line, default_port
    else:
        host, port = line, default_port

    try:
        ip = ipaddress.ip_address(host)
        return {"ip": str(ip), "port": port, "country": country}
    except ValueError:
        try:
            # Fallback for domain names
            ip = socket.gethostbyname(host)
            return {"ip": ip, "port": port, "country": country}
        except socket.gaierror:
            return None


def tcp_ping(ip: str, port: int, timeout=1.5):
    start = time.time()
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            return round((time.time() - start) * 1000, 2)
    except Exception:
        return None


def download_speed_test(ip: str, port: int, stop_event: threading.Event):
    # Simplified speed test logic for brevity
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = (f"GET {DOWNLOAD_PATH} HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\n\r\n").encode()
    speed = 0.0
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, port))
            with ctx.wrap_socket(sock, server_hostname=TEST_HOST) as ss:
                ss.settimeout(5)
                ss.sendall(req)
                start_time = time.time()
                bytes_downloaded = 0
                while time.time() - start_time < 5:
                    if stop_event.is_set(): break
                    chunk = ss.recv(8192)
                    if not chunk: break
                    bytes_downloaded += len(chunk)
                duration = time.time() - start_time
                if duration > 0:
                    speed = round((bytes_downloaded / (1024 * 1024)) / duration, 2)
    except Exception:
        speed = 0.0
    return speed


# --- Worker Threads ---

class LoadTargetsWorker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, path_or_url, default_port):
        super().__init__()
        self.path_or_url = path_or_url
        self.default_port = default_port

    def run(self):
        content = ""
        try:
            if self.path_or_url.startswith(("http://", "https://")):
                response = requests.get(self.path_or_url, timeout=10)
                response.raise_for_status()
                content = response.text
            else:
                with open(self.path_or_url, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
        except Exception as e:
            self.error.emit(f"加载失败: {e}")
            return

        targets = []
        for line in content.splitlines():
            item = parse_ip_port_country_line(line, self.default_port)
            if item:
                targets.append(item)

        if not targets:
            self.error.emit("文件中未找到有效节点。")
            return
        
        self.finished.emit(targets)


class TestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(list)

    def __init__(self, targets, threads, test_type='latency'):
        super().__init__()
        self.targets = targets
        self.threads = threads
        self.test_type = test_type
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run_latency_test(self, item):
        latency = tcp_ping(item["ip"], item["port"])
        if latency is not None:
            item['latency'] = latency
            return item
        return None

    def run_speed_test(self, item):
        speed = download_speed_test(item["ip"], item["port"], self.stop_event)
        item['download_speed'] = speed
        return item

    def run(self):
        if not self.targets:
            self.finished_signal.emit([])
            return

        results = []
        task_func = self.run_latency_test if self.test_type == 'latency' else self.run_speed_test

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(task_func, item): item for item in self.targets}
            total = len(self.targets)
            for i, future in enumerate(as_completed(future_map)):
                if self.stop_event.is_set():
                    self.log.emit("测试已手动停止。")
                    break
                
                self.progress.emit(i + 1, total)
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.result_signal.emit(result)
                except Exception as e:
                    self.log.emit(f"测试异常: {e}")

        # Sort results
        if self.test_type == 'latency':
            results.sort(key=lambda x: x.get('latency', float('inf')))
        else:
            results.sort(key=lambda x: x.get('download_speed', 0), reverse=True)
            
        self.finished_signal.emit(results)


# --- Main Window ---

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("国家分组测速工具 - 高级增强版")
        self.resize(1400, 950)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.all_targets = []
        self.country_checkboxes = {}
        self.current_results = []
        self.worker = None

        self.init_ui()
        self.apply_styles()
        self.show_status("准备就绪", permanent=True)

    def init_ui(self):
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # File & URL Input
        file_group = QGroupBox("1. 加载节点")
        file_layout = QVBoxLayout()
        row1 = QHBoxLayout()
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("输入TXT文件路径或URL链接...")
        btn_browse = QPushButton("...")
        btn_browse.setFixedWidth(40)
        btn_browse.clicked.connect(self.browse_file)
        btn_load = QPushButton("加载")
        btn_load.clicked.connect(self.start_loading_targets)
        row1.addWidget(self.url_edit)
        row1.addWidget(btn_browse)
        row1.addWidget(btn_load)
        file_layout.addLayout(row1)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # Country Selection
        country_group = QGroupBox("2. 选择国家")
        country_layout_main = QVBoxLayout()
        country_top = QHBoxLayout()
        self.country_search_input = QLineEdit()
        self.country_search_input.setPlaceholderText("搜索国家代码...")
        self.country_search_input.textChanged.connect(self.filter_countries)
        btn_select_all = QPushButton("全选")
        btn_unselect_all = QPushButton("全不选")
        btn_select_all.clicked.connect(lambda: self.toggle_countries(True))
        btn_unselect_all.clicked.connect(lambda: self.toggle_countries(False))
        country_top.addWidget(self.country_search_input)
        country_top.addWidget(btn_select_all)
        country_top.addWidget(btn_unselect_all)
        country_layout_main.addLayout(country_top)

        self.country_scroll = QScrollArea()
        self.country_scroll.setWidgetResizable(True)
        self.country_scroll.setFixedHeight(150)
        self.country_widget = QWidget()
        self.country_layout = QGridLayout()
        self.country_widget.setLayout(self.country_layout)
        self.country_scroll.setWidget(self.country_widget)
        country_layout_main.addWidget(self.country_scroll)
        country_group.setLayout(country_layout_main)
        main_layout.addWidget(country_group)

        # Actions
        action_group = QGroupBox("3. 执行测试")
        action_layout = QVBoxLayout()
        row_actions = QHBoxLayout()
        self.btn_latency = QPushButton("延迟测试")
        self.btn_speed = QPushButton("测速")
        self.btn_stop = QPushButton("停止")
        self.btn_latency.clicked.connect(lambda: self.start_test('latency'))
        self.btn_speed.clicked.connect(lambda: self.start_test('speed'))
        self.btn_stop.clicked.connect(self.stop_test)
        row_actions.addWidget(self.btn_latency)
        row_actions.addWidget(self.btn_speed)
        row_actions.addWidget(self.btn_stop)
        row_actions.addStretch()
        action_layout.addLayout(row_actions)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        action_layout.addWidget(self.progress_bar)
        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # Results
        result_group = QGroupBox("4. 查看结果")
        result_layout = QVBoxLayout()
        
        # Two tables side-by-side
        result_h_layout = QHBoxLayout()
        
        # Country Stats
        country_stats_v_layout = QVBoxLayout()
        country_stats_v_layout.addWidget(QLabel("国家统计"))
        self.country_table = QTableWidget(0, 4)
        self.country_table.setHorizontalHeaderLabels(["国家", "数量", "平均延迟", "平均速度"])
        self.country_table.setSortingEnabled(True)
        self.country_table.cellDoubleClicked.connect(self.select_country_from_table)
        country_stats_v_layout.addWidget(self.country_table)
        
        # Node Details
        details_v_layout = QVBoxLayout()
        details_v_layout.addWidget(QLabel("节点明细"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "端口", "国家", "延迟(ms)", "速度(MB/s)"])
        self.table.setSortingEnabled(True)
        self.table.cellDoubleClicked.connect(self.copy_ip_from_table)
        details_v_layout.addWidget(self.table)
        
        result_h_layout.addLayout(country_stats_v_layout, 1) # 1/3 width
        result_h_layout.addLayout(details_v_layout, 2) # 2/3 width
        result_layout.addLayout(result_h_layout)

        # Export & Clear
        export_clear_layout = QHBoxLayout()
        self.btn_export = QPushButton("导出结果")
        self.btn_clear = QPushButton("清空结果")
        self.btn_export.clicked.connect(self.export_results)
        self.btn_clear.clicked.connect(self.clear_results)
        export_clear_layout.addStretch()
        export_clear_layout.addWidget(self.btn_export)
        export_clear_layout.addWidget(self.btn_clear)
        result_layout.addLayout(export_clear_layout)
        
        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)

        self.setStatusBar(QStatusBar(self))

    def apply_styles(self):
        # Apply a modern dark theme
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #1e1f26; color: #f8f8f2; font-size: 14px; }
            QGroupBox { border: 1px solid #44475a; border-radius: 8px; margin-top: 10px; background-color: #282a36; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; color: #8be9fd; font-weight: bold; }
            QLabel { color: #f8f8f2; }
            QLineEdit, QSpinBox, QTextEdit, QTableWidget { background-color: #282a36; border: 1px solid #44475a; border-radius: 5px; padding: 5px; color: #f8f8f2; }
            QPushButton { background-color: #6272a4; border: none; border-radius: 5px; padding: 8px 16px; color: #f8f8f2; }
            QPushButton:hover { background-color: #7082b6; }
            QPushButton:pressed { background-color: #526294; }
            QHeaderView::section { background-color: #44475a; padding: 5px; border: none; color: #bd93f9; font-weight: bold; }
            QTableWidget { gridline-color: #44475a; }
            QProgressBar { border: 1px solid #44475a; border-radius: 5px; text-align: center; background-color: #282a36; }
            QProgressBar::chunk { background-color: #50fa7b; border-radius: 5px; }
            QScrollArea { border: 1px solid #44475a; border-radius: 5px; }
            QStatusBar { color: #f8f8f2; }
        """)

    # --- Core Logic ---
    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择TXT文件", "", "Text Files (*.txt)")
        if path:
            self.url_edit.setText(path)

    def start_loading_targets(self):
        path_or_url = self.url_edit.text().strip()
        if not path_or_url:
            QMessageBox.warning(self, "提示", "请输入文件路径或URL。")
            return
        
        self.show_status(f"正在从 {path_or_url} 加载...", permanent=True)
        self.loader = LoadTargetsWorker(path_or_url, 443) # Assuming default port 443
        self.loader.finished.connect(self.on_targets_loaded)
        self.loader.error.connect(self.on_loading_error)
        self.loader.start()

    def on_targets_loaded(self, targets):
        self.all_targets = targets
        self.clear_results()
        self.build_country_checkboxes()
        self.update_country_stats(self.all_targets)
        self.show_status(f"加载成功，共 {len(targets)} 个节点。", permanent=True)

    def on_loading_error(self, error_msg):
        QMessageBox.critical(self, "加载错误", error_msg)
        self.show_status("加载失败", permanent=True)
    
    def build_country_checkboxes(self):
        # Clear existing checkboxes
        for i in reversed(range(self.country_layout.count())): 
            self.country_layout.itemAt(i).widget().setParent(None)
        self.country_checkboxes.clear()

        stats = defaultdict(int)
        for item in self.all_targets:
            stats[item['country']] += 1
        
        countries = sorted(stats.keys())
        cols = 6
        for i, country in enumerate(countries):
            cb = QCheckBox(f"{country} ({stats[country]})")
            cb.setChecked(True)
            self.country_checkboxes[country] = cb
            self.country_layout.addWidget(cb, i // cols, i % cols)

    def filter_countries(self, text):
        text = text.lower()
        for country, cb in self.country_checkboxes.items():
            cb.setVisible(text in country.lower())

    def toggle_countries(self, state):
        for cb in self.country_checkboxes.values():
            if cb.isVisible():
                cb.setChecked(state)

    def start_test(self, test_type):
        selected_countries = {c for c, cb in self.country_checkboxes.items() if cb.isChecked()}
        if not selected_countries:
            QMessageBox.warning(self, "提示", "请至少选择一个国家。")
            return

        targets_to_test = []
        if test_type == 'latency':
            targets_to_test = [t for t in self.all_targets if t['country'] in selected_countries]
            self.show_status("正在进行延迟测试...", permanent=True)
        elif test_type == 'speed':
            if not self.current_results or 'latency' not in self.current_results[0]:
                 QMessageBox.warning(self, "提示", "请先进行延迟测试。")
                 return
            targets_to_test = [r for r in self.current_results if r['country'] in selected_countries]
            self.show_status("正在进行速度测试...", permanent=True)

        if not targets_to_test:
            QMessageBox.information(self, "提示", "没有符合条件的节点可供测试。")
            self.show_status("准备就绪", permanent=True)
            return

        self.clear_results(clear_log=False)
        self.worker = TestWorker(targets_to_test, 20, test_type) # Assuming 20 threads
        self.worker.progress.connect(self.update_progress)
        self.worker.result_signal.connect(self.on_result_received)
        self.worker.finished_signal.connect(self.on_test_finished)
        self.worker.start()

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.show_status("正在停止测试...", permanent=True)
    
    def on_result_received(self, result):
        self.current_results.append(result)
        self.add_result_to_table(result)
        self.update_country_stats(self.current_results)
    
    def on_test_finished(self, final_results):
        self.current_results = final_results
        self.update_table_with_results(final_results)
        self.update_country_stats(final_results)
        self.show_status(f"测试完成，共获得 {len(final_results)} 条有效结果。", permanent=True)
        
        # Auto-sort
        if self.worker and self.worker.test_type == 'latency':
            self.table.sortItems(3, Qt.AscendingOrder) # Sort by latency
        elif self.worker and self.worker.test_type == 'speed':
            self.table.sortItems(4, Qt.DescendingOrder) # Sort by speed

    # --- UI Update and Interaction ---
    def update_progress(self, current, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.statusBar().showMessage(f"进度: {current}/{total}")

    def show_status(self, message, timeout=5000, permanent=False):
        if permanent:
            self.statusBar().showMessage(message)
        else:
            self.statusBar().showMessage(message, timeout)

    def add_result_to_table(self, item, is_batch=False):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(item['ip']))
        self.table.setItem(row, 1, NumericTableWidgetItem(str(item['port'])))
        self.table.setItem(row, 2, QTableWidgetItem(item['country']))
        self.table.setItem(row, 3, NumericTableWidgetItem(f"{item.get('latency', 0):.2f}"))
        self.table.setItem(row, 4, NumericTableWidgetItem(f"{item.get('download_speed', 0):.2f}"))
        if not is_batch: self.table.scrollToBottom()

    def update_table_with_results(self, results):
        self.table.setRowCount(0)
        self.table.setSortingEnabled(False)
        for item in results:
            self.add_result_to_table(item, is_batch=True)
        self.table.setSortingEnabled(True)

    def update_country_stats(self, results):
        self.country_table.setRowCount(0)
        self.country_table.setSortingEnabled(False)
        stats = defaultdict(lambda: {'count': 0, 'latencies': [], 'speeds': []})
        for item in results:
            country = item['country']
            stats[country]['count'] += 1
            if 'latency' in item: stats[country]['latencies'].append(item['latency'])
            if 'download_speed' in item: stats[country]['speeds'].append(item['download_speed'])
        
        for country, data in sorted(stats.items()):
            avg_latency = sum(data['latencies']) / len(data['latencies']) if data['latencies'] else 0
            avg_speed = sum(data['speeds']) / len(data['speeds']) if data['speeds'] else 0
            row = self.country_table.rowCount()
            self.country_table.insertRow(row)
            self.country_table.setItem(row, 0, QTableWidgetItem(country))
            self.country_table.setItem(row, 1, NumericTableWidgetItem(str(data['count'])))
            self.country_table.setItem(row, 2, NumericTableWidgetItem(f"{avg_latency:.2f}"))
            self.country_table.setItem(row, 3, NumericTableWidgetItem(f"{avg_speed:.2f}"))
        self.country_table.setSortingEnabled(True)

    def copy_ip_from_table(self, row, col):
        ip = self.table.item(row, 0).text()
        port = int(float(self.table.item(row, 1).text()))
        clipboard_text = format_ip_port(ip, port)
        QApplication.clipboard().setText(clipboard_text)
        self.show_status(f"已复制: {clipboard_text}")

    def select_country_from_table(self, row, col):
        country = self.country_table.item(row, 0).text()
        for c, cb in self.country_checkboxes.items():
            cb.setChecked(c == country)
        self.show_status(f"已自动选择国家: {country}")

    def clear_results(self, clear_log=True):
        self.current_results = []
        self.table.setRowCount(0)
        self.country_table.setRowCount(0)
        self.update_progress(0, 1)
        if clear_log: self.statusBar().clearMessage() # Assuming no separate log widget
    
    def export_results(self):
        if not self.current_results:
            QMessageBox.warning(self, "提示", "没有结果可以导出。")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "导出结果", "results.txt", "Text Files (*.txt)")
        if not path:
            return

        with open(path, 'w', encoding='utf-8') as f:
            for item in self.current_results:
                line = f"{format_ip_port(item['ip'], item['port'])}#({item['country']}) " \
                       f"Delay: {item.get('latency', 'N/A'):.2f}ms, " \
                       f"Speed: {item.get('download_speed', 'N/A'):.2f}MB/s\n"
                f.write(line)
        self.show_status(f"结果已导出到 {path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
