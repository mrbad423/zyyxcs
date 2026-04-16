import sys
import os
import time
import socket
import ssl
import ipaddress
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox
)

TEST_HOST = "speed.cloudflare.com"
DOWNLOAD_PATH = "/__down?bytes=50000000"


def format_ip_port(ip: str, port: int) -> str:
    """格式化 IP:端口，IPv6 自动加 []"""
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def split_countries(country_text: str):
    """
    解析国家代码输入框，如:
    HK,JP,SG,TW,US
    """
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


def parse_ip_port_country_line(line: str, default_port: int = 443):
    """
    支持格式：
    1.1.1.1
    1.1.1.1:443
    1.1.1.1:443#HK
    1.1.1.1#HK
    [2606:4700::1111]:443#TW
    2606:4700::1111#JP
    """
    line = line.strip()
    if not line:
        return None

    country = "UNKNOWN"

    # 提取国家代码
    if "#" in line:
        line_part, country_part = line.split("#", 1)
        line = line_part.strip()
        country = country_part.strip().upper() if country_part.strip() else "UNKNOWN"

    if not line:
        return None

    # 处理 [IPv6]:port
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

    # 尝试纯 IP（IPv4 / IPv6）
    try:
        ipaddress.ip_address(line)
        return {"ip": line, "port": default_port, "country": country}
    except Exception:
        pass

    # 尝试 IPv4:port
    if ":" in line:
        try:
            ip, port = line.rsplit(":", 1)
            ip = ip.strip()
            port = int(port.strip())
            ipaddress.ip_address(ip)
            return {"ip": ip, "port": port, "country": country}
        except Exception:
            return None

    return None


def tcp_ping(ip: str, port: int, timeout=1.5):
    """TCP 延迟测试，返回毫秒"""
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


def speed_test_single(ip: str, port: int, country: str, stop_event: threading.Event):
    """单个节点测速"""
    latency = tcp_ping(ip, port, timeout=1.5)

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
        "latency": latency if latency is not None else 9999.0,
        "download_speed": speed,
    }


def export_grouped_by_country(results, countries, topn_each):
    """按国家分组，并取每个国家前 N"""
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
        items.sort(key=lambda x: x["download_speed"], reverse=True)
        if topn_each > 0:
            items = items[:topn_each]
        export_items.extend(items)

    return export_items


class SpeedTestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(list)

    def __init__(self, file_path, default_port=443, threads=20):
        super().__init__()
        self.file_path = file_path
        self.default_port = default_port
        self.threads = threads
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        if not os.path.exists(self.file_path):
            self.log.emit("文件不存在。")
            self.finished_signal.emit([])
            return

        targets = []
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                item = parse_ip_port_country_line(line, self.default_port)
                if item:
                    targets.append(item)

        if not targets:
            self.log.emit("没有解析到可测速的 IP。")
            self.finished_signal.emit([])
            return

        self.log.emit(f"已加载 {len(targets)} 个目标，开始测速...")
        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(
                    speed_test_single,
                    item["ip"],
                    item["port"],
                    item["country"],
                    self.stop_event
                ): item
                for item in targets
            }

            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    self.log.emit("测速已停止。")
                    break

                try:
                    result = future.result()
                    results.append(result)
                    self.result_signal.emit(result)

                    completed += 1
                    self.progress.emit(completed, len(targets))
                    self.log.emit(
                        f"[{completed}/{len(targets)}] "
                        f"{format_ip_port(result['ip'], result['port'])} | "
                        f"{result['country']} | "
                        f"{result['latency']:.2f} ms | "
                        f"{result['download_speed']:.2f} MB/s"
                    )
                except Exception as e:
                    completed += 1
                    self.progress.emit(completed, len(targets))
                    self.log.emit(f"[{completed}/{len(targets)}] 测速异常: {e}")

        results.sort(key=lambda x: x["download_speed"], reverse=True)
        self.finished_signal.emit(results)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("按TXT国家代码分国家测速工具")
        self.resize(1100, 760)

        self.file_path = ""
        self.results = []
        self.worker = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # 文件选择
        row1 = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("请选择TXT文件...")
        btn_browse = QPushButton("选择文件")
        btn_browse.clicked.connect(self.choose_file)
        row1.addWidget(QLabel("TXT文件:"))
        row1.addWidget(self.file_edit)
        row1.addWidget(btn_browse)
        layout.addLayout(row1)

        # 参数设置
        row2 = QHBoxLayout()

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)

        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 500)
        self.thread_input.setValue(20)

        self.country_input = QLineEdit()
        self.country_input.setPlaceholderText("留空=导出全部国家，例如：HK,JP,SG,TW,US")

        self.topn_input = QSpinBox()
        self.topn_input.setRange(0, 100000)
        self.topn_input.setValue(10)
        self.topn_input.setToolTip("每个国家导出前N条，0表示全部导出")

        row2.addWidget(QLabel("默认端口(仅TXT未写端口时使用):"))
        row2.addWidget(self.port_input)
        row2.addSpacing(10)

        row2.addWidget(QLabel("线程数:"))
        row2.addWidget(self.thread_input)
        row2.addSpacing(10)

        row2.addWidget(QLabel("筛选国家:"))
        row2.addWidget(self.country_input)
        row2.addSpacing(10)

        row2.addWidget(QLabel("每国前N条:"))
        row2.addWidget(self.topn_input)

        layout.addLayout(row2)

        # 按钮
        row3 = QHBoxLayout()
        self.btn_start = QPushButton("开始测速")
        self.btn_stop = QPushButton("停止")
        self.btn_export = QPushButton("导出结果")
        self.btn_clear = QPushButton("清空结果")

        self.btn_start.clicked.connect(self.start_test)
        self.btn_stop.clicked.connect(self.stop_test)
        self.btn_export.clicked.connect(self.export_results)
        self.btn_clear.clicked.connect(self.clear_results)

        row3.addWidget(self.btn_start)
        row3.addWidget(self.btn_stop)
        row3.addWidget(self.btn_export)
        row3.addWidget(self.btn_clear)
        layout.addLayout(row3)

        # 结果表格
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "端口", "国家代码", "延迟(ms)", "速度(MB/s)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        # 日志
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        layout.addWidget(QLabel("运行日志:"))
        layout.addWidget(self.log_edit)

        self.setLayout(layout)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择TXT文件", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.file_path = path
            self.file_edit.setText(path)

    def append_log(self, text):
        self.log_edit.append(text)

    def add_result_row(self, item):
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(item["ip"]))
        self.table.setItem(row, 1, QTableWidgetItem(str(item["port"])))
        self.table.setItem(row, 2, QTableWidgetItem(item["country"]))
        self.table.setItem(row, 3, QTableWidgetItem(f"{item['latency']:.2f}"))
        self.table.setItem(row, 4, QTableWidgetItem(f"{item['download_speed']:.2f}"))

    def start_test(self):
        file_path = self.file_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "提示", "请先选择TXT文件。")
            return

        self.results = []
        self.table.setRowCount(0)
        self.log_edit.clear()

        default_port = self.port_input.value()
        threads = self.thread_input.value()

        self.worker = SpeedTestWorker(file_path, default_port, threads)
        self.worker.log.connect(self.append_log)
        self.worker.result_signal.connect(self.on_result)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

        self.btn_start.setEnabled(False)
        self.append_log("开始测速...")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("正在停止测速...")

    def on_result(self, item):
        self.results.append(item)
        self.add_result_row(item)

    def on_finished(self, results):
        self.results = results
        self.btn_start.setEnabled(True)
        self.append_log(f"测速完成，共得到 {len(results)} 条结果。")

    def clear_results(self):
        self.results = []
        self.table.setRowCount(0)
        self.log_edit.clear()

    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, "提示", "没有可导出的结果。")
            return

        countries = split_countries(self.country_input.text())
        topn_each = self.topn_input.value()

        export_items = export_grouped_by_country(self.results, countries, topn_each)

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

        with open(save_path, "w", encoding="utf-8") as f:
            for item in export_items:
                ip_port = format_ip_port(item["ip"], item["port"])
                line = f"{ip_port}#{item['country']}+{item['download_speed']:.2f}MB/s"
                f.write(line + "\n")

        QMessageBox.information(self, "完成", f"已导出 {len(export_items)} 条结果到：\n{save_path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
