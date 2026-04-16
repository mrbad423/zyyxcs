import sys
import os
import time
import socket
import ipaddress
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox
)


FAILED_LATENCY = 9999.0


def format_ip_port(ip: str, port: int) -> str:
    """格式化 IP:端口，IPv6 自动加 []"""
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def normalize_key(ip: str, port: int, country: str) -> str:
    return f"{ip}|{port}|{country.upper()}"


def split_countries(country_text: str):
    """解析国家代码列表，如 HK,JP,SG,TW,US"""
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
    支持：
    1.1.1.1
    1.1.1.1:443
    1.1.1.1:443#US
    1.1.1.1#US
    [2606:4700::1111]:443#JP
    2606:4700::1111#JP
    """
    line = line.strip()
    if not line:
        return None

    country = "UNKNOWN"

    if "#" in line:
        line_part, country_part = line.split("#", 1)
        line = line_part.strip()
        country = country_part.strip().upper() if country_part.strip() else "UNKNOWN"

    if not line:
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
            return {"ip": ip, "port": port, "country": country}
        except Exception:
            return None

    # 纯 IP（IPv4/IPv6）
    try:
        ipaddress.ip_address(line)
        return {"ip": line, "port": default_port, "country": country}
    except Exception:
        pass

    # IPv4:port
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


def tcp_ping_once(ip: str, port: int, timeout=1.5):
    """单次 TCP 延迟测试，返回毫秒；失败返回 None"""
    start = time.perf_counter()
    sock = None
    try:
        if ":" in ip:
            addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addrinfo[0]
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
        end = time.perf_counter()
        return round((end - start) * 1000, 2)
    except Exception:
        return None
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


def tcp_ping_stable(ip: str, port: int, attempts=3, timeout=1.5, stop_event=None):
    """
    更稳的延迟测试：
    - 连测 attempts 次
    - 保留成功结果
    - 返回 best / avg / success_count
    """
    latencies = []

    for _ in range(attempts):
        if stop_event and stop_event.is_set():
            break
        latency = tcp_ping_once(ip, port, timeout=timeout)
        if latency is not None:
            latencies.append(latency)
        time.sleep(0.05)

    if not latencies:
        return {
            "best_latency": FAILED_LATENCY,
            "avg_latency": FAILED_LATENCY,
            "success_count": 0,
            "attempts": attempts,
        }

    best_latency = min(latencies)
    avg_latency = round(sum(latencies) / len(latencies), 2)

    return {
        "best_latency": best_latency,
        "avg_latency": avg_latency,
        "success_count": len(latencies),
        "attempts": attempts,
    }


def latency_test_single(ip: str, port: int, country: str, attempts: int, timeout: float, stop_event: threading.Event):
    result = tcp_ping_stable(ip, port, attempts=attempts, timeout=timeout, stop_event=stop_event)
    return {
        "ip": ip,
        "port": port,
        "country": country,
        "latency": result["best_latency"],      # 排序主字段：最佳延迟
        "avg_latency": result["avg_latency"],   # 展示附加字段：平均延迟
        "success_count": result["success_count"],
        "attempts": result["attempts"],
    }


def export_grouped_by_country(results, countries, topn_each, exclude_timeout=True):
    """
    按国家分组，按最佳延迟排序，取每个国家前N条
    """
    grouped = defaultdict(list)

    for item in results:
        country = item.get("country", "UNKNOWN").upper()
        if countries and country not in countries:
            continue
        if exclude_timeout and item["latency"] >= FAILED_LATENCY:
            continue
        grouped[country].append(item)

    export_items = []
    target_countries = countries if countries else sorted(grouped.keys())

    for country in target_countries:
        items = grouped.get(country, [])
        items.sort(key=lambda x: (x["latency"], x["avg_latency"]))
        if topn_each > 0:
            items = items[:topn_each]
        export_items.extend(items)

    return export_items


class LatencyTestWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(list)

    def __init__(self, file_path, default_port=443, threads=50, attempts=3, timeout=1.5):
        super().__init__()
        self.file_path = file_path
        self.default_port = default_port
        self.threads = threads
        self.attempts = attempts
        self.timeout = timeout
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        if not os.path.exists(self.file_path):
            self.log.emit("文件不存在。")
            self.finished_signal.emit([])
            return

        raw_targets = []
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                item = parse_ip_port_country_line(line, self.default_port)
                if item:
                    raw_targets.append(item)

        if not raw_targets:
            self.log.emit("没有解析到可测试的 IP。")
            self.finished_signal.emit([])
            return

        # 去重
        seen = set()
        targets = []
        dup_count = 0
        for item in raw_targets:
            key = normalize_key(item["ip"], item["port"], item["country"])
            if key in seen:
                dup_count += 1
                continue
            seen.add(key)
            targets.append(item)

        self.log.emit(f"原始目标 {len(raw_targets)} 个，去重后 {len(targets)} 个，重复 {dup_count} 个。")
        self.log.emit(
            f"开始延迟测试：线程={self.threads}，每个节点测试 {self.attempts} 次，超时={self.timeout:.2f}s"
        )

        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(
                    latency_test_single,
                    item["ip"],
                    item["port"],
                    item["country"],
                    self.attempts,
                    self.timeout,
                    self.stop_event
                ): item
                for item in targets
            }

            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    self.log.emit("测试已停止。")
                    break

                completed += 1
                self.progress.emit(completed, len(targets))

                try:
                    result = future.result()
                    results.append(result)
                    self.result_signal.emit(result)

                    if result["latency"] >= FAILED_LATENCY:
                        self.log.emit(
                            f"[{completed}/{len(targets)}] "
                            f"{format_ip_port(result['ip'], result['port'])} | "
                            f"{result['country']} | 失败"
                        )
                    else:
                        self.log.emit(
                            f"[{completed}/{len(targets)}] "
                            f"{format_ip_port(result['ip'], result['port'])} | "
                            f"{result['country']} | "
                            f"最佳 {result['latency']:.2f} ms | "
                            f"平均 {result['avg_latency']:.2f} ms | "
                            f"成功 {result['success_count']}/{result['attempts']}"
                        )
                except Exception as e:
                    self.log.emit(f"[{completed}/{len(targets)}] 测试异常: {e}")

        results.sort(key=lambda x: (x["latency"], x["avg_latency"]))
        self.finished_signal.emit(results)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("增强版：按TXT国家代码分国家延迟测试")
        self.resize(1120, 760)

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
        self.thread_input.setRange(1, 1000)
        self.thread_input.setValue(50)

        self.attempts_input = QSpinBox()
        self.attempts_input.setRange(1, 10)
        self.attempts_input.setValue(3)

        self.timeout_input = QLineEdit()
        self.timeout_input.setText("1.5")
        self.timeout_input.setPlaceholderText("超时秒数，如 1.5")

        row2.addWidget(QLabel("默认端口:"))
        row2.addWidget(self.port_input)
        row2.addSpacing(10)

        row2.addWidget(QLabel("线程数:"))
        row2.addWidget(self.thread_input)
        row2.addSpacing(10)

        row2.addWidget(QLabel("每节点测试次数:"))
        row2.addWidget(self.attempts_input)
        row2.addSpacing(10)

        row2.addWidget(QLabel("单次超时(秒):"))
        row2.addWidget(self.timeout_input)

        layout.addLayout(row2)

        row3 = QHBoxLayout()

        self.country_input = QLineEdit()
        self.country_input.setPlaceholderText("留空=全部国家，例如 HK,JP,DE,US")

        self.topn_input = QSpinBox()
        self.topn_input.setRange(0, 100000)
        self.topn_input.setValue(10)

        self.success_only_checkbox = QCheckBox("仅导出成功节点")
        self.success_only_checkbox.setChecked(True)

        row3.addWidget(QLabel("筛选国家:"))
        row3.addWidget(self.country_input)
        row3.addSpacing(10)

        row3.addWidget(QLabel("每国前N条:"))
        row3.addWidget(self.topn_input)
        row3.addSpacing(10)

        row3.addWidget(self.success_only_checkbox)

        layout.addLayout(row3)

        # 按钮
        row4 = QHBoxLayout()
        self.btn_start = QPushButton("开始测试")
        self.btn_stop = QPushButton("停止")
        self.btn_export = QPushButton("导出结果")
        self.btn_clear = QPushButton("清空结果")

        self.btn_start.clicked.connect(self.start_test)
        self.btn_stop.clicked.connect(self.stop_test)
        self.btn_export.clicked.connect(self.export_results)
        self.btn_clear.clicked.connect(self.clear_results)

        row4.addWidget(self.btn_start)
        row4.addWidget(self.btn_stop)
        row4.addWidget(self.btn_export)
        row4.addWidget(self.btn_clear)
        layout.addLayout(row4)

        # 结果表格
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["IP", "端口", "国家代码", "最佳延迟(ms)", "平均延迟(ms)", "成功次数"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        # 日志
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        layout.addWidget(QLabel("运行日志:"))
        layout.addWidget(self.log_edit)

        self.setLayout(layout)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择TXT文件", "", "Text Files (*.txt);;All Files (*)"
        )
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
        self.table.setItem(row, 4, QTableWidgetItem(f"{item['avg_latency']:.2f}"))
        self.table.setItem(row, 5, QTableWidgetItem(f"{item['success_count']}/{item['attempts']}"))

    def start_test(self):
        file_path = self.file_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "提示", "请先选择TXT文件。")
            return

        try:
            timeout = float(self.timeout_input.text().strip())
            if timeout <= 0:
                raise ValueError
        except Exception:
            QMessageBox.warning(self, "提示", "超时秒数格式不正确，例如 1.5")
            return

        self.results = []
        self.table.setRowCount(0)
        self.log_edit.clear()

        default_port = self.port_input.value()
        threads = self.thread_input.value()
        attempts = self.attempts_input.value()

        self.worker = LatencyTestWorker(
            file_path=file_path,
            default_port=default_port,
            threads=threads,
            attempts=attempts,
            timeout=timeout
        )
        self.worker.log.connect(self.append_log)
        self.worker.result_signal.connect(self.on_result)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

        self.btn_start.setEnabled(False)
        self.append_log("开始延迟测试...")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("正在停止...")

    def on_result(self, item):
        self.results.append(item)
        self.add_result_row(item)

    def on_finished(self, results):
        self.results = results
        self.btn_start.setEnabled(True)
        self.append_log(f"测试完成，共得到 {len(results)} 条结果。")

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
        success_only = self.success_only_checkbox.isChecked()

        export_items = export_grouped_by_country(
            self.results,
            countries,
            topn_each,
            exclude_timeout=success_only
        )

        if not export_items:
            QMessageBox.warning(self, "提示", "没有符合筛选条件的结果。")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存结果",
            "all.txt",
            "Text Files (*.txt)"
        )
        if not save_path:
            return

        with open(save_path, "w", encoding="utf-8") as f:
            for item in export_items:
                # 严格按 all.txt 同格式导出
                line = f"{format_ip_port(item['ip'], item['port'])}#{item['country']}"
                f.write(line + "\n")

        QMessageBox.information(
            self,
            "完成",
            f"已导出 {len(export_items)} 条结果到：\n{save_path}"
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
