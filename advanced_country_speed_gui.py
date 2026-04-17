import sys
import os
import time
import socket
import ssl
import ipaddress
import threading
import re
import base64
import json
import statistics
from urllib.parse import urlparse, quote
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QTimer
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox, QSpinBox, QCheckBox,
    QScrollArea, QGridLayout, QProgressBar, QGroupBox, QComboBox, QDoubleSpinBox
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


def timed_download_speed_test(ip: str, port: int, stop_event: threading.Event,
                              duration_sec=2.0, slow_abort_threshold_mb=0.2,
                              warmup_ratio=0.15):
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

    result = {
        "speed": 0.0,
        "bytes": 0,
        "duration": 0.0,
        "aborted_early": False,
        "success": False,
    }

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
        ss.settimeout(1.0)
        ss.sendall(req)

        start = time.time()
        warmup_sec = max(0.0, duration_sec * warmup_ratio)
        measure_start = start + warmup_sec

        header_data = b""
        header_done = False
        measured_body_size = 0

        while time.time() - start < duration_sec:
            if stop_event.is_set():
                break
            try:
                buf = ss.recv(16384)
                now = time.time()
                if not buf:
                    break

                if not header_done:
                    header_data += buf
                    if b"\r\n\r\n" in header_data:
                        header_done = True
                        body = header_data.split(b"\r\n\r\n", 1)[1]
                        if now >= measure_start:
                            measured_body_size += len(body)
                else:
                    if now >= measure_start:
                        measured_body_size += len(buf)

                elapsed = now - start
                effective_elapsed = max(now - measure_start, 0.001)

                if elapsed >= min(1.0, duration_sec):
                    current_speed = (measured_body_size / 1024 / 1024) / effective_elapsed
                    if current_speed < slow_abort_threshold_mb:
                        result["aborted_early"] = True
                        break

            except socket.timeout:
                continue

        end = time.time()
        try:
            ss.close()
        except Exception:
            pass

        measured_duration = max(end - measure_start, 0.001)
        speed = round((measured_body_size / 1024 / 1024) / measured_duration, 2)

        result["speed"] = speed
        result["bytes"] = measured_body_size
        result["duration"] = measured_duration
        result["success"] = measured_body_size > 0

    except Exception:
        pass

    return result


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


def normalize_webdav_url(url: str):
    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if not url.lower().endswith("/webdav"):
        url += "/webdav"
    return url


def build_webdav_url(base_url: str, remote_dir: str, filename: str = None):
    base_url = base_url.strip().rstrip("/")
    parts = []

    if remote_dir:
        parts.extend([quote(p) for p in remote_dir.strip("/").split("/") if p.strip()])

    if filename is not None:
        parts.append(quote(filename))

    if parts:
        return base_url + "/" + "/".join(parts)
    return base_url


def make_basic_auth(username: str, password: str):
    return base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")


def open_request(req: Request, timeout=30, verify_ssl=True):
    context = None
    if not verify_ssl:
        context = ssl._create_unverified_context()
    return urlopen(req, timeout=timeout, context=context)


def test_webdav_propfind(base_url: str, username: str, password: str, verify_ssl: bool = True):
    auth = make_basic_auth(username, password)

    req = Request(base_url.rstrip("/"), method="PROPFIND")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Depth", "0")
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        with open_request(req, timeout=20, verify_ssl=verify_ssl) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return True, f"PROPFIND成功: HTTP {resp.status}\n{body}"
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            pass
        return False, f"PROPFIND失败: HTTP {e.code} {e.reason}\n{body}"
    except URLError as e:
        return False, f"连接失败: {e}"


def webdav_path_exists(url: str, username: str, password: str, verify_ssl=True):
    auth = make_basic_auth(username, password)
    req = Request(url.rstrip("/"), method="PROPFIND")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Depth", "0")
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with open_request(req, timeout=20, verify_ssl=verify_ssl) as resp:
            return True, resp.status, ""
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            pass
        if e.code == 404:
            return False, e.code, body
        return True, e.code, body
    except Exception as e:
        return False, None, str(e)


def webdav_mkcol(url: str, username: str, password: str, verify_ssl=True):
    auth = make_basic_auth(username, password)
    req = Request(url.rstrip("/"), data=b"", method="MKCOL")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("User-Agent", "Mozilla/5.0")
    req.add_header("Connection", "close")
    req.add_header("Content-Length", "0")

    try:
        with open_request(req, timeout=20, verify_ssl=verify_ssl) as resp:
            return True, resp.status, ""
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            pass
        if e.code in (200, 201, 204, 301, 302, 307, 308, 405):
            return True, e.code, body
        return False, e.code, body
    except Exception as e:
        return False, None, str(e)


def ensure_webdav_remote_dir(base_url: str, remote_dir: str, username: str, password: str,
                             verify_ssl=True, logger=None):
    remote_dir = (remote_dir or "").strip().strip("/")
    if not remote_dir:
        if logger:
            logger("未设置远程目录，跳过MKCOL。")
        return

    parts = [p for p in remote_dir.split("/") if p.strip()]
    current_parts = []

    for part in parts:
        current_parts.append(part)
        current_dir = "/".join(current_parts)
        current_url = build_webdav_url(base_url, current_dir)

        if logger:
            logger(f"检查远程目录：{current_url}")

        exists, status, detail = webdav_path_exists(
            current_url, username, password, verify_ssl=verify_ssl
        )
        if exists:
            if logger:
                logger(f"远程目录已存在：{current_url} (HTTP {status})")
            continue

        if logger:
            logger(f"开始创建远程目录：{current_url}")

        ok, mk_status, mk_detail = webdav_mkcol(
            current_url, username, password, verify_ssl=verify_ssl
        )
        if ok:
            if logger:
                logger(f"远程目录创建成功：{current_url} (HTTP {mk_status})")
            continue

        raise Exception(
            f"创建WebDAV目录失败\n"
            f"目录URL: {current_url}\n"
            f"HTTP状态码: {mk_status}\n"
            f"响应内容:\n{mk_detail}"
        )


def upload_to_webdav(base_url: str, remote_dir: str, filename: str, content: bytes,
                     username: str, password: str, verify_ssl: bool = True,
                     auto_create_dir: bool = True, logger=None):
    if auto_create_dir:
        ensure_webdav_remote_dir(
            base_url=base_url,
            remote_dir=remote_dir,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            logger=logger
        )

    full_url = build_webdav_url(base_url, remote_dir, filename)
    auth = make_basic_auth(username, password)

    req = Request(full_url, data=content, method="PUT")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    req.add_header("Content-Length", str(len(content)))
    req.add_header("User-Agent", "Mozilla/5.0")
    req.add_header("Connection", "close")

    try:
        with open_request(req, timeout=30, verify_ssl=verify_ssl) as resp:
            body = ""
            try:
                body = resp.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            return {
                "status": resp.status,
                "url": full_url,
                "body": body
            }

    except HTTPError as e:
        error_body = ""
        headers = ""
        try:
            error_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            pass
        try:
            headers = str(e.headers)
        except Exception:
            pass

        raise Exception(
            f"WebDAV上传失败\n"
            f"HTTP状态码: {e.code}\n"
            f"原因: {e.reason}\n"
            f"URL: {full_url}\n"
            f"响应头:\n{headers}\n"
            f"响应内容:\n{error_body}"
        )

    except URLError as e:
        raise Exception(f"WebDAV连接失败\nURL: {full_url}\n错误: {e}")


def calc_score(item, speed_weight=0.7, latency_weight=0.3):
    speed = float(item.get("download_speed", 0.0) or 0.0)
    latency = float(item.get("latency", 999999.0) or 999999.0)
    latency_score = 1000.0 / max(latency + 1.0, 1.0)
    return speed * speed_weight + latency_score * latency_weight


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

    def __init__(self, targets, threads=80):
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
            result["score"] = 0.0
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

    def __init__(self, targets, threads=10, repeats=2, duration_sec=2.0,
                 slow_abort_threshold=0.2, agg_mode="median",
                 speed_weight=0.7, latency_weight=0.3):
        super().__init__()
        self.targets = targets
        self.threads = threads
        self.repeats = repeats
        self.duration_sec = duration_sec
        self.slow_abort_threshold = slow_abort_threshold
        self.agg_mode = agg_mode
        self.speed_weight = speed_weight
        self.latency_weight = latency_weight
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def aggregate_speed(self, samples):
        valid = [x for x in samples if x >= 0]
        if not valid:
            return 0.0
        if self.agg_mode == "mean":
            return round(sum(valid) / len(valid), 2)
        return round(statistics.median(valid), 2)

    def run(self):
        if not self.targets:
            self.log.emit("没有可测速的节点，请先进行延迟测试。")
            self.finished_signal.emit([])
            return

        self.log.emit(
            f"开始对 {len(self.targets)} 个节点进行测速..."
            f" | 并发={self.threads}"
            f" | 次数={self.repeats}"
            f" | 时长={self.duration_sec}s"
            f" | 聚合={self.agg_mode}"
        )

        results = []
        completed = 0

        def speed_one(item):
            result = dict(item)
            samples = []
            early_abort_count = 0

            for i in range(self.repeats):
                if self.stop_event.is_set():
                    break
                test_result = timed_download_speed_test(
                    item["ip"],
                    item["port"],
                    self.stop_event,
                    duration_sec=self.duration_sec,
                    slow_abort_threshold_mb=self.slow_abort_threshold
                )
                speed = float(test_result["speed"])
                samples.append(speed)
                if test_result["aborted_early"]:
                    early_abort_count += 1

                if self.repeats >= 2 and i == 0 and speed < self.slow_abort_threshold:
                    break

            result["speed_samples"] = samples
            result["download_speed"] = self.aggregate_speed(samples)
            result["score"] = round(
                calc_score(result, self.speed_weight, self.latency_weight), 4
            )
            result["early_abort_count"] = early_abort_count
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
                        f"{result['download_speed']:.2f} MB/s | "
                        f"样本={result.get('speed_samples', [])} | "
                        f"评分={result['score']:.4f}"
                    )
                except Exception as e:
                    self.log.emit(f"[{completed}/{len(self.targets)}] 测速异常: {e}")

        results.sort(
            key=lambda x: (x.get("score", 0.0), x.get("download_speed", 0.0)),
            reverse=True
        )
        self.finished_signal.emit(results)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("国家分组测速工具 - 最终修正版")
        self.resize(1350, 920)

        self.all_targets = []
        self.country_checkboxes = {}
        self.latency_results = []
        self.speed_candidates = []
        self.results = []
        self.worker = None
        self.url_loader = None

        self._loading_settings = False
        self.settings = QSettings("mrbad423", "advanced_country_speed_gui")

        self.init_ui()
        self.apply_styles()
        self.load_settings()
        self.bind_auto_save()

        QTimer.singleShot(0, self.auto_reload_last_source)

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(14, 14, 14, 14)

        title = QLabel("国家分组测速工具 - 最终修正版")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

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
        self.url_edit.setPlaceholderText("输入TXT链接，例如：https://example.com/all.txt")
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

        self.latency_thread_input = QSpinBox()
        self.latency_thread_input.setRange(1, 500)
        self.latency_thread_input.setValue(80)

        self.speed_thread_input = QSpinBox()
        self.speed_thread_input.setRange(1, 200)
        self.speed_thread_input.setValue(10)

        row3.addWidget(QLabel("默认端口:"))
        row3.addWidget(self.port_input)
        row3.addSpacing(12)
        row3.addWidget(QLabel("延迟线程:"))
        row3.addWidget(self.latency_thread_input)
        row3.addSpacing(12)
        row3.addWidget(QLabel("测速线程:"))
        row3.addWidget(self.speed_thread_input)
        row3.addStretch()
        import_layout.addLayout(row3)

        row4 = QHBoxLayout()
        self.country_input = QLineEdit()
        self.country_input.setPlaceholderText("导出筛选国家，留空=全部，例如：HK,JP,SG")

        self.topn_input = QSpinBox()
        self.topn_input.setRange(0, 100000)
        self.topn_input.setValue(10)
        self.topn_input.setToolTip("每国导出前N条，0表示全部")

        self.speed_topn_input = QSpinBox()
        self.speed_topn_input.setRange(1, 100000)
        self.speed_topn_input.setValue(50)
        self.speed_topn_input.setToolTip("每个勾选国家在延迟测试后，仅取前N个低延迟节点进入测速")

        row4.addWidget(QLabel("导出筛选国家:"))
        row4.addWidget(self.country_input)
        row4.addSpacing(12)
        row4.addWidget(QLabel("每国前N条:"))
        row4.addWidget(self.topn_input)
        row4.addSpacing(12)
        row4.addWidget(QLabel("每国进入测速前N个:"))
        row4.addWidget(self.speed_topn_input)

        import_layout.addLayout(row4)
        import_group.setLayout(import_layout)
        main_layout.addWidget(import_group)

        strategy_group = QGroupBox("测速策略")
        strategy_layout = QVBoxLayout()

        strategy_row1 = QHBoxLayout()

        self.speed_repeat_input = QSpinBox()
        self.speed_repeat_input.setRange(1, 10)
        self.speed_repeat_input.setValue(2)

        self.speed_duration_input = QDoubleSpinBox()
        self.speed_duration_input.setRange(0.5, 30.0)
        self.speed_duration_input.setSingleStep(0.5)
        self.speed_duration_input.setValue(2.0)

        self.slow_abort_input = QDoubleSpinBox()
        self.slow_abort_input.setRange(0.0, 1000.0)
        self.slow_abort_input.setSingleStep(0.1)
        self.slow_abort_input.setValue(0.2)
        self.slow_abort_input.setSuffix(" MB/s")

        self.agg_mode_combo = QComboBox()
        self.agg_mode_combo.addItem("中位数", "median")
        self.agg_mode_combo.addItem("平均值", "mean")

        strategy_row1.addWidget(QLabel("每节点测速次数:"))
        strategy_row1.addWidget(self.speed_repeat_input)
        strategy_row1.addSpacing(12)
        strategy_row1.addWidget(QLabel("单次测速时长:"))
        strategy_row1.addWidget(self.speed_duration_input)
        strategy_row1.addSpacing(12)
        strategy_row1.addWidget(QLabel("低速提前终止阈值:"))
        strategy_row1.addWidget(self.slow_abort_input)
        strategy_row1.addSpacing(12)
        strategy_row1.addWidget(QLabel("测速聚合方式:"))
        strategy_row1.addWidget(self.agg_mode_combo)
        strategy_row1.addStretch()

        strategy_layout.addLayout(strategy_row1)

        strategy_row2 = QHBoxLayout()

        self.speed_weight_input = QDoubleSpinBox()
        self.speed_weight_input.setRange(0.0, 1.0)
        self.speed_weight_input.setSingleStep(0.1)
        self.speed_weight_input.setValue(0.7)

        self.latency_weight_input = QDoubleSpinBox()
        self.latency_weight_input.setRange(0.0, 1.0)
        self.latency_weight_input.setSingleStep(0.1)
        self.latency_weight_input.setValue(0.3)

        strategy_row2.addWidget(QLabel("速度权重:"))
        strategy_row2.addWidget(self.speed_weight_input)
        strategy_row2.addSpacing(12)
        strategy_row2.addWidget(QLabel("延迟权重:"))
        strategy_row2.addWidget(self.latency_weight_input)
        strategy_row2.addStretch()

        strategy_layout.addLayout(strategy_row2)
        strategy_group.setLayout(strategy_layout)
        main_layout.addWidget(strategy_group)

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
        self.webdav_url_edit.setPlaceholderText("WebDAV地址，例如：https://dav.example.com/webdav")
        export_row2.addWidget(QLabel("WebDAV地址:"))
        export_row2.addWidget(self.webdav_url_edit)
        export_layout.addLayout(export_row2)

        export_row3 = QHBoxLayout()
        self.webdav_user_edit = QLineEdit()
        self.webdav_user_edit.setPlaceholderText("WebDAV用户名")
        self.webdav_pass_edit = QLineEdit()
        self.webdav_pass_edit.setPlaceholderText("WebDAV密码")
        self.webdav_pass_edit.setEchoMode(QLineEdit.Password)

        self.toggle_password_btn = QPushButton("显示密码")
        self.toggle_password_btn.setCheckable(True)
        self.toggle_password_btn.clicked.connect(self.toggle_password_visibility)

        export_row3.addWidget(QLabel("用户名:"))
        export_row3.addWidget(self.webdav_user_edit)
        export_row3.addWidget(QLabel("密码:"))
        export_row3.addWidget(self.webdav_pass_edit)
        export_row3.addWidget(self.toggle_password_btn)
        export_layout.addLayout(export_row3)

        export_row4 = QHBoxLayout()
        self.webdav_dir_edit = QLineEdit()
        self.webdav_dir_edit.setPlaceholderText("远程目录，例如：测速结果/2025/04")
        export_row4.addWidget(QLabel("远程目录:"))
        export_row4.addWidget(self.webdav_dir_edit)
        export_layout.addLayout(export_row4)

        export_group.setLayout(export_layout)
        main_layout.addWidget(export_group)

        action_group = QGroupBox("操作")
        action_layout = QVBoxLayout()

        row_action = QHBoxLayout()
        self.btn_latency = QPushButton("延迟测试")
        self.btn_speed = QPushButton("测速")
        self.btn_stop = QPushButton("停止")
        self.btn_test_webdav = QPushButton("测试WebDAV")
        self.btn_export = QPushButton("导出到本地")
        self.btn_export_webdav = QPushButton("导出到WebDAV")
        self.btn_clear = QPushButton("清空结果")

        self.btn_latency.clicked.connect(self.start_latency_test)
        self.btn_speed.clicked.connect(self.start_speed_test)
        self.btn_stop.clicked.connect(self.stop_test)
        self.btn_test_webdav.clicked.connect(self.test_webdav_connection)
        self.btn_export.clicked.connect(self.export_results_local)
        self.btn_export_webdav.clicked.connect(self.export_results_webdav)
        self.btn_clear.clicked.connect(self.clear_results)

        self.btn_speed.setEnabled(False)

        row_action.addWidget(self.btn_latency)
        row_action.addWidget(self.btn_speed)
        row_action.addWidget(self.btn_stop)
        row_action.addWidget(self.btn_test_webdav)
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
            QLineEdit, QSpinBox, QTextEdit, QComboBox, QDoubleSpinBox {
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

    def bind_auto_save(self):
        self.file_edit.textChanged.connect(self.save_settings)
        self.url_edit.textChanged.connect(self.save_settings)
        self.country_input.textChanged.connect(self.save_settings)
        self.country_search_edit.textChanged.connect(self.save_settings)
        self.export_name_edit.textChanged.connect(self.save_settings)
        self.webdav_url_edit.textChanged.connect(self.save_settings)
        self.webdav_user_edit.textChanged.connect(self.save_settings)
        self.webdav_pass_edit.textChanged.connect(self.save_settings)
        self.webdav_dir_edit.textChanged.connect(self.save_settings)

        self.port_input.valueChanged.connect(self.save_settings)
        self.latency_thread_input.valueChanged.connect(self.save_settings)
        self.speed_thread_input.valueChanged.connect(self.save_settings)
        self.topn_input.valueChanged.connect(self.save_settings)
        self.speed_topn_input.valueChanged.connect(self.save_settings)
        self.speed_repeat_input.valueChanged.connect(self.save_settings)
        self.speed_duration_input.valueChanged.connect(self.save_settings)
        self.slow_abort_input.valueChanged.connect(self.save_settings)
        self.agg_mode_combo.currentIndexChanged.connect(self.save_settings)
        self.speed_weight_input.valueChanged.connect(self.save_settings)
        self.latency_weight_input.valueChanged.connect(self.save_settings)

    def load_settings(self):
        self._loading_settings = True
        try:
            geometry = self.settings.value("window/geometry")
            if geometry:
                self.restoreGeometry(geometry)

            self.file_edit.setText(self.settings.value("import/file_path", ""))
            self.url_edit.setText(self.settings.value("import/url", ""))
            self.port_input.setValue(self.settings.value("import/default_port", 443, type=int))
            self.latency_thread_input.setValue(self.settings.value("test/latency_threads", 80, type=int))
            self.speed_thread_input.setValue(self.settings.value("test/speed_threads", 10, type=int))

            self.country_input.setText(self.settings.value("export/countries", ""))
            self.topn_input.setValue(self.settings.value("export/topn_each", 10, type=int))
            self.country_search_edit.setText(self.settings.value("country/search", ""))
            self.export_name_edit.setText(self.settings.value("export/filename", "export_result.txt"))

            self.speed_topn_input.setValue(self.settings.value("test/speed_topn", 50, type=int))
            self.speed_repeat_input.setValue(self.settings.value("test/speed_repeats", 2, type=int))
            self.speed_duration_input.setValue(self.settings.value("test/speed_duration", 2.0, type=float))
            self.slow_abort_input.setValue(self.settings.value("test/slow_abort_threshold", 0.2, type=float))

            agg_value = self.settings.value("test/agg_mode", "median")
            idx = self.agg_mode_combo.findData(agg_value)
            if idx >= 0:
                self.agg_mode_combo.setCurrentIndex(idx)

            self.speed_weight_input.setValue(self.settings.value("test/speed_weight", 0.7, type=float))
            self.latency_weight_input.setValue(self.settings.value("test/latency_weight", 0.3, type=float))

            self.webdav_url_edit.setText(self.settings.value("webdav/url", ""))
            self.webdav_user_edit.setText(self.settings.value("webdav/username", ""))
            self.webdav_pass_edit.setText(self.settings.value("webdav/password", ""))
            self.webdav_dir_edit.setText(self.settings.value("webdav/remote_dir", ""))
        finally:
            self._loading_settings = False

    def save_country_selection(self):
        if self._loading_settings:
            return
        selected = [country for country, cb in self.country_checkboxes.items() if cb.isChecked()]
        self.settings.setValue("country/selected", json.dumps(selected, ensure_ascii=False))

    def restore_country_selection(self):
        saved = self.settings.value("country/selected", "[]")
        try:
            selected = set(json.loads(saved))
        except Exception:
            selected = set()

        if not self.country_checkboxes:
            return

        if not selected:
            for cb in self.country_checkboxes.values():
                cb.setChecked(True)
            return

        for country, cb in self.country_checkboxes.items():
            cb.setChecked(country in selected)

    def save_settings(self):
        if self._loading_settings:
            return

        self.settings.setValue("window/geometry", self.saveGeometry())
        self.settings.setValue("import/file_path", self.file_edit.text().strip())
        self.settings.setValue("import/url", self.url_edit.text().strip())
        self.settings.setValue("import/default_port", self.port_input.value())
        self.settings.setValue("test/latency_threads", self.latency_thread_input.value())
        self.settings.setValue("test/speed_threads", self.speed_thread_input.value())

        self.settings.setValue("export/countries", self.country_input.text().strip())
        self.settings.setValue("export/topn_each", self.topn_input.value())
        self.settings.setValue("country/search", self.country_search_edit.text().strip())
        self.settings.setValue("export/filename", self.export_name_edit.text().strip())

        self.settings.setValue("test/speed_topn", self.speed_topn_input.value())
        self.settings.setValue("test/speed_repeats", self.speed_repeat_input.value())
        self.settings.setValue("test/speed_duration", self.speed_duration_input.value())
        self.settings.setValue("test/slow_abort_threshold", self.slow_abort_input.value())
        self.settings.setValue("test/agg_mode", self.agg_mode_combo.currentData())
        self.settings.setValue("test/speed_weight", self.speed_weight_input.value())
        self.settings.setValue("test/latency_weight", self.latency_weight_input.value())

        self.settings.setValue("webdav/url", self.webdav_url_edit.text().strip())
        self.settings.setValue("webdav/username", self.webdav_user_edit.text().strip())
        self.settings.setValue("webdav/password", self.webdav_pass_edit.text())
        self.settings.setValue("webdav/remote_dir", self.webdav_dir_edit.text().strip())
        self.save_country_selection()

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

    def toggle_password_visibility(self):
        if self.toggle_password_btn.isChecked():
            self.webdav_pass_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_password_btn.setText("隐藏密码")
        else:
            self.webdav_pass_edit.setEchoMode(QLineEdit.Password)
            self.toggle_password_btn.setText("显示密码")

    def auto_reload_last_source(self):
        file_path = self.file_edit.text().strip()
        url = self.url_edit.text().strip()

        if file_path and os.path.exists(file_path):
            self.append_log(f"启动时自动重新加载上次本地文件：{file_path}")
            ok = self.load_targets_from_file(file_path)
            if ok:
                self.append_log(f"本地文件自动加载完成，共解析到 {len(self.all_targets)} 个目标。")
                self.set_status("已自动加载上次本地TXT")
                return
            else:
                self.append_log("上次本地文件自动加载失败。")

        if url and (url.startswith("http://") or url.startswith("https://")):
            self.append_log(f"启动时自动重新加载上次 URL：{url}")
            self.set_status("正在自动加载上次URL")
            self.url_loader = LoadUrlWorker(url)
            self.url_loader.log.connect(self.append_log)
            self.url_loader.finished_signal.connect(self.on_auto_url_loaded)
            self.url_loader.start()

    def on_auto_url_loaded(self, success, content):
        if not success:
            self.append_log(f"上次URL自动加载失败：{content}")
            self.set_status("自动加载上次URL失败")
            return

        self.all_targets = []
        for line in content.splitlines():
            item = parse_ip_port_country_line(line, self.port_input.value())
            if item:
                self.all_targets.append(item)

        if not self.all_targets:
            self.append_log("上次URL内容中没有解析到可用目标。")
            self.set_status("上次URL无可用内容")
            return

        self.build_country_checkboxes()
        self.append_log(f"上次URL自动加载完成，共解析到 {len(self.all_targets)} 个目标。")
        self.set_status("已自动加载上次URL")

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
            checkbox.stateChanged.connect(self.save_country_selection)
            self.country_checkboxes[country] = checkbox
            row = idx // cols
            col = idx % cols
            self.country_layout.addWidget(checkbox, row, col)

        self.restore_country_selection()
        self.filter_country_checkboxes()

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
        self.save_country_selection()

    def unselect_all_countries(self):
        for cb in self.country_checkboxes.values():
            cb.setChecked(False)
        self.save_country_selection()

    def start_latency_test(self):
        if not self.all_targets:
            QMessageBox.warning(self, "提示", "请先导入本地TXT或远程TXT链接。")
            return

        selected_targets = self.get_selected_targets()
        if not selected_targets:
            QMessageBox.warning(self, "提示", "请至少勾选一个国家进行测试。")
            return

        self.latency_results = []
        self.speed_candidates = []
        self.results = []
        self.log_edit.clear()
        self.reset_progress()

        threads = self.latency_thread_input.value()
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
        topn = self.speed_topn_input.value()

        grouped = defaultdict(list)
        for item in results:
            country = item.get("country", "UNKNOWN").upper()
            grouped[country].append(item)

        selected_countries = self.get_selected_countries()
        speed_candidates = []

        self.append_log("按国家分别筛选进入测速的候选节点：")
        for country in selected_countries:
            items = grouped.get(country, [])
            items.sort(key=lambda x: x.get("latency", 999999.0))
            picked = items[:topn]
            speed_candidates.extend(picked)

            self.append_log(
                f"  {country}: 有延迟 {len(items)} 个，进入测速 {len(picked)} 个（前 {topn} 个）"
            )

        self.speed_candidates = speed_candidates

        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True if self.speed_candidates else False)
        self.set_status("延迟测试完成")

        self.append_log(f"延迟测试完成，保留 {len(results)} 个有延迟节点。")
        self.append_log(
            f"已按每个勾选国家分别取前 {topn} 个低延迟节点进入测速，"
            f"最终测速候选总数：{len(self.speed_candidates)}"
        )

    def start_speed_test(self):
        if not self.speed_candidates:
            QMessageBox.warning(self, "提示", "请先进行延迟测试，且必须有可测速候选节点。")
            return

        speed_weight = self.speed_weight_input.value()
        latency_weight = self.latency_weight_input.value()
        total_weight = speed_weight + latency_weight

        if total_weight <= 0:
            QMessageBox.warning(self, "提示", "速度权重和延迟权重之和必须大于 0。")
            return

        speed_weight = speed_weight / total_weight
        latency_weight = latency_weight / total_weight

        grouped = defaultdict(int)
        for item in self.speed_candidates:
            grouped[item.get("country", "UNKNOWN").upper()] += 1

        self.append_log("本次进入测速的国家分布：")
        for country in self.get_selected_countries():
            self.append_log(f"  {country}: {grouped.get(country, 0)} 个")

        self.results = []
        self.reset_progress()

        threads = self.speed_thread_input.value()
        repeats = self.speed_repeat_input.value()
        duration_sec = self.speed_duration_input.value()
        slow_abort_threshold = self.slow_abort_input.value()
        agg_mode = self.agg_mode_combo.currentData()

        self.worker = SpeedTestWorker(
            self.speed_candidates,
            threads=threads,
            repeats=repeats,
            duration_sec=duration_sec,
            slow_abort_threshold=slow_abort_threshold,
            agg_mode=agg_mode,
            speed_weight=speed_weight,
            latency_weight=latency_weight
        )
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished_signal.connect(self.on_speed_finished)
        self.worker.start()

        self.btn_latency.setEnabled(False)
        self.btn_speed.setEnabled(False)
        self.set_status("测速中")
        self.append_log(
            f"开始测速：候选节点={len(self.speed_candidates)} | "
            f"测速线程={threads} | 次数={repeats} | 时长={duration_sec}s | 聚合={agg_mode}"
        )

    def on_speed_finished(self, results):
        self.results = results
        self.btn_latency.setEnabled(True)
        self.btn_speed.setEnabled(True)
        self.set_status("测速完成")
        self.append_log(f"测速完成，共得到 {len(results)} 条结果。当前按综合评分排序。")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.append_log("正在停止任务...")
            self.set_status("停止中")

    def clear_results(self):
        self.latency_results = []
        self.speed_candidates = []
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

            if self.results:
                items = [
                    x for x in items
                    if float(x.get("download_speed", 0.0) or 0.0) > 0
                ]

                items.sort(
                    key=lambda x: (x.get("score", 0.0), x.get("download_speed", 0.0)),
                    reverse=True
                )
            else:
                items.sort(key=lambda x: x.get("latency", 999999.0))

            if topn_each > 0:
                items = items[:topn_each]

            export_items.extend(items)

            if self.results:
                self.append_log(
                    f"导出国家 {country}：测速成功 {len(items)} 条"
                    + (f"（按每国前 {topn_each} 条）" if topn_each > 0 else "（全部导出）")
                )
            else:
                self.append_log(
                    f"导出国家 {country}：延迟结果 {len(items)} 条"
                    + (f"（按每国前 {topn_each} 条）" if topn_each > 0 else "（全部导出）")
                )

        if not export_items:
            if self.results:
                return None, "没有符合条件的测速成功结果可导出。"
            return None, "没有符合筛选条件的结果。"

        return export_items, None

    def test_webdav_connection(self):
        base_url = normalize_webdav_url(self.webdav_url_edit.text())
        username = self.webdav_user_edit.text().strip()
        password = self.webdav_pass_edit.text()

        self.webdav_url_edit.setText(base_url)

        if not base_url:
            QMessageBox.warning(self, "提示", "请输入WebDAV地址。")
            return
        if not username:
            QMessageBox.warning(self, "提示", "请输入WebDAV用户名。")
            return

        try:
            ok, msg = test_webdav_propfind(base_url, username, password, verify_ssl=True)
            self.append_log(msg)
            if ok:
                QMessageBox.information(self, "成功", f"WebDAV 测试成功：\n{base_url}")
            else:
                QMessageBox.warning(self, "失败", msg)
        except Exception as e:
            self.append_log(f"测试WebDAV失败：{e}")
            QMessageBox.warning(self, "失败", f"测试WebDAV失败：\n{e}")

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

        base_url = normalize_webdav_url(self.webdav_url_edit.text())
        username = self.webdav_user_edit.text().strip()
        password = self.webdav_pass_edit.text()
        remote_dir = self.webdav_dir_edit.text().strip()
        filename = ensure_txt_filename(self.export_name_edit.text())

        self.webdav_url_edit.setText(base_url)

        if not base_url:
            QMessageBox.warning(self, "提示", "请输入WebDAV地址。")
            return
        if not username:
            QMessageBox.warning(self, "提示", "请输入WebDAV用户名。")
            return

        try:
            ok, msg = test_webdav_propfind(base_url, username, password, verify_ssl=True)
            self.append_log(msg)
            if not ok:
                QMessageBox.warning(self, "失败", f"WebDAV连接测试失败：\n{msg}")
                return

            content = build_export_text(export_items).encode("utf-8")
            result = upload_to_webdav(
                base_url=base_url,
                remote_dir=remote_dir,
                filename=filename,
                content=content,
                username=username,
                password=password,
                verify_ssl=True,
                auto_create_dir=True,
                logger=self.append_log
            )
            self.append_log(f"已导出 {len(export_items)} 条结果到WebDAV：{result['url']} (HTTP {result['status']})")
            if result["body"]:
                self.append_log(f"服务器响应：{result['body']}")
            QMessageBox.information(self, "完成", f"已成功上传到 WebDAV：\n{result['url']}")
        except Exception as e:
            self.append_log(f"导出到WebDAV失败：{e}")
            QMessageBox.warning(self, "失败", f"导出到WebDAV失败：\n{e}")

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setOrganizationName("mrbad423")
    app.setApplicationName("advanced_country_speed_gui")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
