import sys
import time
import ssl
import socket
import ipaddress
import urllib.request
import concurrent.futures
import threading
from datetime import datetime
from collections import defaultdict

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit,
    QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QFileDialog, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor


TEST_HOST = "speed.cloudflare.com"
DEFAULT_URL = "https://zip.cm.edu.kg/all.txt"


def parse_ip_port_line(line: str, default_port: int = 443):
    line = line.strip()
    if not line:
        return None

    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None

    if line.startswith("[") and "]" in line:
        try:
            host_part, rest = line.split("]", 1)
            ip = host_part[1:].strip()
            port = default_port
            if rest.startswith(":"):
                port = int(rest[1:].strip())
            ipaddress.ip_address(ip)
            return {"ip": ip, "port": port}
        except Exception:
            return None

    if line.count(":") == 1 and "." in line:
        try:
            ip, port = line.rsplit(":", 1)
            ip = ip.strip()
            port = int(port.strip())
            ipaddress.ip_address(ip)
            return {"ip": ip, "port": port}
        except Exception:
            return None

    try:
        ipaddress.ip_address(line)
        return {"ip": line, "port": default_port}
    except Exception:
        return None


def format_ip_port(ip: str, port: int):
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def tcp_ping(ip: str, port: int, timeout: float = 1.5):
    start = time.time()
    try:
        if ":" in ip:
            addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addrinfo[0]
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            sock.close()
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.close()
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None


def get_iata_code_from_ip(ip: str, timeout: int = 3):
    test_host = "speed.cloudflare.com"

    if ":" in ip:
        urls = [
            f"https://[{ip}]/cdn-cgi/trace",
            f"http://[{ip}]/cdn-cgi/trace",
        ]
    else:
        urls = [
            f"https://{ip}/cdn-cgi/trace",
            f"http://{ip}/cdn-cgi/trace",
        ]

    for url in urls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if url.startswith("https://"):
                use_ssl = True
                host = url[8:].split("/")[0].strip("[]")
            else:
                use_ssl = False
                host = url[7:].split("/")[0].strip("[]")

            port = 443 if use_ssl else 80

            if ":" in host:
                addrinfo = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
                family, socktype, proto, canonname, sockaddr = addrinfo[0]
                s = socket.socket(family, socktype, proto)
                s.settimeout(timeout)
                s.connect(sockaddr)
            else:
                s = socket.create_connection((host, port), timeout=timeout)

            if use_ssl:
                s = ctx.wrap_socket(s, server_hostname=test_host)

            request = (
                "GET /cdn-cgi/trace HTTP/1.1\r\n"
                f"Host: {test_host}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode()

            s.sendall(request)

            data = b""
            body = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        header_end = data.find(b"\r\n\r\n")
                        body = data[header_end + 4:]
                        break
                except socket.timeout:
                    break

            s.close()

            response_text = body.decode("utf-8", errors="ignore")
            for line in response_text.splitlines():
                if line.startswith("colo="):
                    colo_value = line.split("=", 1)[1].strip()
                    if colo_value and colo_value.upper() != "UNKNOWN":
                        return colo_value.upper()
        except Exception:
            continue

    return None


def speed_test_single(ip: str, port: int, stop_event: threading.Event):
    latency = tcp_ping(ip, port, timeout=1.5)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = (
        "GET /__down?bytes=50000000 HTTP/1.1\r\n"
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
        ss.sendall(req)

        start = time.time()
        data = b""
        header_done = False
        body_size = 0

        while time.time() - start < 3:
            if stop_event.is_set():
                break
            buf = ss.recv(8192)
            if not buf:
                break
            if not header_done:
                data += buf
                if b"\r\n\r\n" in data:
                    header_done = True
                    body_size += len(data.split(b"\r\n\r\n", 1)[1])
            else:
                body_size += len(buf)

        ss.close()
        duration = time.time() - start
        speed = round((body_size / 1024 / 1024) / max(duration, 0.1), 2)

    except Exception:
        speed = 0.0

    colo = get_iata_code_from_ip(ip, timeout=3)

    return {
        "ip": ip,
        "port": port,
        "latency": latency if latency is not None else 9999.0,
        "download_speed": speed,
        "iata": colo if colo else "UNKNOWN"
    }


def split_regions(region_text: str):
    if not region_text.strip():
        return []
    parts = region_text.replace("，", ",").split(",")
    result = []
    seen = set()
    for part in parts:
        code = part.strip().upper()
        if code and code not in seen:
            seen.add(code)
            result.append(code)
    return result


def export_grouped_by_region(results, regions, topn_each):
    grouped = defaultdict(list)

    for item in results:
        iata = item.get("iata", "UNKNOWN").upper()
        if regions and iata not in regions:
            continue
        grouped[iata].append(item)

    export_items = []

    target_regions = regions if regions else sorted(grouped.keys())

    for region in target_regions:
        items = grouped.get(region, [])
        items.sort(key=lambda x: x["download_speed"], reverse=True)

        if topn_each > 0:
            items = items[:topn_each]

        export_items.extend(items)

    return export_items


class SpeedTestWorker(QThread):
    progress = Signal(int, int)
    log = Signal(str)
    finished_result = Signal(list)

    def __init__(self, url: str, default_port: int, max_count: int, concurrency: int):
        super().__init__()
        self.url = url.strip()
        self.default_port = default_port
        self.max_count = max_count
        self.concurrency = concurrency
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def fetch_txt(self):
        req = urllib.request.Request(self.url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="ignore").splitlines()

    def run(self):
        results = []
        try:
            self.log.emit(f"开始下载: {self.url}")
            lines = self.fetch_txt()

            parsed = []
            seen = set()

            for line in lines:
                item = parse_ip_port_line(line, self.default_port)
                if item:
                    key = f"{item['ip']}:{item['port']}"
                    if key not in seen:
                        seen.add(key)
                        parsed.append(item)

            if not parsed:
                self.log.emit("未解析到有效 IP")
                self.finished_result.emit([])
                return

            self.log.emit(f"解析到 {len(parsed)} 个目标")
            targets = parsed[:min(self.max_count, len(parsed))]
            self.log.emit(f"开始并发测速 {len(targets)} 个目标，并发数: {self.concurrency}")

            completed = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                future_map = {
                    executor.submit(speed_test_single, item["ip"], item["port"], self.stop_event): item
                    for item in targets
                }

                for future in concurrent.futures.as_completed(future_map):
                    if self.stop_event.is_set():
                        self.log.emit("用户已停止测速")
                        break

                    item = future_map[future]
                    completed += 1

                    try:
                        result = future.result()
                        results.append(result)
                        self.log.emit(
                            f"[{completed}/{len(targets)}] {format_ip_port(result['ip'], result['port'])} | "
                            f"{result['iata']} | {result['download_speed']:.2f} MB/s"
                        )
                    except Exception as e:
                        self.log.emit(
                            f"[{completed}/{len(targets)}] {format_ip_port(item['ip'], item['port'])} 测速失败: {e}"
                        )

                    self.progress.emit(completed, len(targets))

            results.sort(key=lambda x: x["download_speed"], reverse=True)
            self.finished_result.emit(results)

        except Exception as e:
            self.log.emit(f"发生错误: {e}")
            self.finished_result.emit(results)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TXT 并发测速工具 - 最终增强版")
        self.resize(1120, 780)

        self.worker = None
        self.results = []

        self.init_ui()

    def init_ui(self):
        font = QFont("Microsoft YaHei", 10)
        main = QVBoxLayout(self)

        title = QLabel("TXT 并发测速工具 - 最终增强版")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Microsoft YaHei", 18, QFont.Bold))
        main.addWidget(title)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("TXT链接:"))
        self.url_input = QLineEdit(DEFAULT_URL)
        self.url_input.setFont(font)
        row1.addWidget(self.url_input)
        main.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("默认端口:"))
        self.port_input = QLineEdit("443")
        self.port_input.setFixedWidth(80)
        row2.addWidget(self.port_input)

        row2.addSpacing(15)

        row2.addWidget(QLabel("测速数量:"))
        self.count_input = QLineEdit("50")
        self.count_input.setFixedWidth(80)
        row2.addWidget(self.count_input)

        row2.addSpacing(15)

        row2.addWidget(QLabel("并发数:"))
        self.concurrency_input = QLineEdit("10")
        self.concurrency_input.setFixedWidth(80)
        row2.addWidget(self.concurrency_input)

        row2.addStretch()

        self.btn_start = QPushButton("开始测速")
        self.btn_start.clicked.connect(self.start_test)
        row2.addWidget(self.btn_start)

        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_test)
        row2.addWidget(self.btn_stop)

        main.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("导出地区码:"))
        self.export_regions_input = QLineEdit()
        self.export_regions_input.setPlaceholderText("如 HKG,SIN,NRT；留空=全部地区")
        self.export_regions_input.setMinimumWidth(260)
        row3.addWidget(self.export_regions_input)

        row3.addSpacing(15)

        row3.addWidget(QLabel("每个地区前N个:"))
        self.export_topn_input = QLineEdit("10")
        self.export_topn_input.setFixedWidth(100)
        row3.addWidget(self.export_topn_input)

        row3.addStretch()

        self.btn_export = QPushButton("导出TXT")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.export_txt)
        row3.addWidget(self.btn_export)

        main.addLayout(row3)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        main.addWidget(self.progress)

        self.status = QLabel("就绪")
        main.addWidget(self.status)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(180)
        main.addWidget(self.log_box)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["排名", "IP", "端口", "地区码", "延迟(ms)", "速度(MB/s)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        main.addWidget(self.table)

    def append_log(self, text):
        self.log_box.append(text)

    def start_test(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入 TXT 链接")
            return

        try:
            port = int(self.port_input.text().strip())
            if not (1 <= port <= 65535):
                raise ValueError
        except Exception:
            QMessageBox.warning(self, "提示", "默认端口无效")
            return

        try:
            count = int(self.count_input.text().strip())
            if not (1 <= count <= 5000):
                raise ValueError
        except Exception:
            QMessageBox.warning(self, "提示", "测速数量无效，范围 1-5000")
            return

        try:
            concurrency = int(self.concurrency_input.text().strip())
            if not (1 <= concurrency <= 200):
                raise ValueError
        except Exception:
            QMessageBox.warning(self, "提示", "并发数无效，范围 1-200")
            return

        self.results = []
        self.table.setRowCount(0)
        self.log_box.clear()
        self.progress.setValue(0)
        self.status.setText("测速中...")

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_export.setEnabled(False)

        self.worker = SpeedTestWorker(url, port, count, concurrency)
        self.worker.progress.connect(self.update_progress)
        self.worker.log.connect(self.append_log)
        self.worker.finished_result.connect(self.on_finished)
        self.worker.start()

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("正在停止任务...")
            self.status.setText("正在停止...")

    def update_progress(self, current, total):
        if total > 0:
            self.progress.setValue(int(current * 100 / total))
        self.status.setText(f"测速中 {current}/{total}")

    def on_finished(self, results):
        self.results = results
        self.progress.setValue(100 if results else 0)
        self.status.setText(f"完成，共 {len(results)} 条结果")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_export.setEnabled(bool(results))
        self.fill_table(results)

    def fill_table(self, results):
        self.table.setRowCount(0)

        for idx, item in enumerate(results, 1):
            row = self.table.rowCount()
            self.table.insertRow(row)

            latency_text = f"{item['latency']:.2f}" if item["latency"] != 9999.0 else "N/A"
            values = [
                str(idx),
                item["ip"],
                str(item["port"]),
                item["iata"],
                latency_text,
                f"{item['download_speed']:.2f}",
            ]

            for col, val in enumerate(values):
                table_item = QTableWidgetItem(val)
                table_item.setTextAlignment(Qt.AlignCenter)

                if col == 4 and item["latency"] != 9999.0:
                    if item["latency"] < 100:
                        table_item.setForeground(QColor("#16A34A"))
                    elif item["latency"] < 200:
                        table_item.setForeground(QColor("#D97706"))
                    else:
                        table_item.setForeground(QColor("#DC2626"))

                if col == 5:
                    speed = item["download_speed"]
                    if speed >= 20:
                        table_item.setForeground(QColor("#16A34A"))
                    elif speed >= 10:
                        table_item.setForeground(QColor("#D97706"))
                    else:
                        table_item.setForeground(QColor("#DC2626"))

                self.table.setItem(row, col, table_item)

    def export_txt(self):
        if not self.results:
            QMessageBox.information(self, "提示", "没有结果可导出")
            return

        regions = split_regions(self.export_regions_input.text().strip())

        topn_text = self.export_topn_input.text().strip()
        if not topn_text:
            topn_each = 0
        else:
            try:
                topn_each = int(topn_text)
                if topn_each < 0:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(self, "提示", "每个地区前N个必须是大于等于0的数字")
                return

        export_items = export_grouped_by_region(self.results, regions, topn_each)

        if not export_items:
            QMessageBox.information(self, "提示", "筛选后没有可导出的结果")
            return

        if regions:
            self.append_log(f"导出地区: {', '.join(regions)}")
        else:
            self.append_log("导出地区: 全部地区")

        if topn_each > 0:
            self.append_log(f"每个地区各导出前 {topn_each} 个最快节点")
        else:
            self.append_log("每个地区导出全部节点")

        default_name = "speed_results"
        if regions:
            default_name += "_" + "_".join(regions)
        else:
            default_name += "_ALL"

        if topn_each > 0:
            default_name += f"_eachTop{topn_each}"

        default_name += f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出TXT",
            default_name,
            "Text Files (*.txt)"
        )
        if not path:
            return

        if not path.lower().endswith(".txt"):
            path += ".txt"

        try:
            with open(path, "w", encoding="utf-8") as f:
                for item in export_items:
                    ip_port = format_ip_port(item["ip"], item["port"])
                    line = f"{ip_port}#{item['iata']}+{item['download_speed']:.2f}MB/s"
                    f.write(line + "\n")

            self.append_log(f"导出完成，共写入 {len(export_items)} 条")
            QMessageBox.information(self, "成功", f"已导出到:\n{path}")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败:\n{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
