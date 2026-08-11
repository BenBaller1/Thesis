from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import logging
import random
import re
import signal
import sqlite3
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

LOG = logging.getLogger("app_latency_measurement")


class MeasurementError(RuntimeError):
    pass

class DnsSilenceTimeoutError(MeasurementError):
    pass

class NetworkDegradationError(MeasurementError):
    pass
#most of the functions are just copied from the first script
def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def which_or_die(binary: str) -> str:
    from shutil import which
    found = which(binary)
    if not found:
        raise MeasurementError(f"Required binary not found in PATH: {binary}")
    return found

def load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(argv: list[str], *, timeout: Optional[float] = None, capture_output: bool = True, cwd: Optional[Path] = None, check: bool = False,) -> subprocess.CompletedProcess[str]:
    LOG.debug("Executing: %s", " ".join(argv))
    return subprocess.run(
        argv,
        timeout=timeout,
        capture_output=capture_output,
        cwd=str(cwd) if cwd else None,
        text=True,
        check=check,
    )
#helper
def parse_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None

def parse_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None

def parse_ping_rtt(output: str) -> Optional[dict[str, float]]:
    m = re.search(
        r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    if not m:
        return None
    result = {
        "min": float(m.group(1)),
        "avg": float(m.group(2)),
        "max": float(m.group(3)),
        "mdev": float(m.group(4)),
    }
    loss = re.search(r"([0-9.]+)%\s+packet\s+loss", output, re.IGNORECASE)
    result["loss_pct"] = float(loss.group(1)) if loss else 0.0
    return result


def safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)

@dataclass(frozen=True)
class ProtocolSpec:
    name: str
    upstream: str
    port: Optional[int] = None
    sni: Optional[str] = None
    extra_args: tuple[str, ...] = ()

    @staticmethod
    def from_dict(name: str, data: dict[str, Any]) -> "ProtocolSpec":
        upstream = str(data["upstream"]).strip()
        port = data.get("port")
        if port is not None:
            port = int(port)
        sni = data.get("sni")
        if sni is not None:
            sni = str(sni).strip()
        extra_args = tuple(str(x) for x in (data.get("extra_args") or []))
        return ProtocolSpec(
            name=name.lower(),
            upstream=upstream,
            port=port,
            sni=sni,
            extra_args=extra_args,
        )

# most of these specs are configured through the config
@dataclass(frozen=True)
class AppSpec:
    name: str
    package: str
    launch_activity: str
    launch_action: Optional[str] = "android.intent.action.MAIN"
    launch_category: Optional[str] = "android.intent.category.LAUNCHER"
    launch_extra_args: tuple[str, ...] = ()
    clear_data: bool = True
    force_stop_before_launch: bool = True
    launch_timeout_seconds: float = 30.0
    ready_timeout_seconds: float = 60.0

    @staticmethod
    def from_dict(data: dict[str, Any], fallback_name: Optional[str] = None) -> "AppSpec":
        name = str(data.get("name", fallback_name or "app")).strip()
        launch_action = data.get("launch_action", "android.intent.action.MAIN")
        launch_category = data.get("launch_category", "android.intent.category.LAUNCHER")
        return AppSpec(
            name=name,
            package=str(data["package"]).strip(),
            launch_activity=str(data["launch_activity"]).strip(),
            launch_action=str(launch_action).strip() if launch_action is not None else None,
            launch_category=str(launch_category).strip() if launch_category is not None else None,
            launch_extra_args=tuple(str(x) for x in (data.get("launch_extra_args") or [])),
            clear_data=bool(data.get("clear_data", True)),
            force_stop_before_launch=bool(data.get("force_stop_before_launch", True)),
            launch_timeout_seconds=float(data.get("launch_timeout_seconds", 30.0)),
            ready_timeout_seconds=float(data.get("ready_timeout_seconds", 60.0)),
        )


@dataclass(frozen=True)
class EmulatorSpec:
    avd_name: str
    emulator_binary: str = "emulator"
    adb_binary: str = "adb"
    wipe_data: bool = True
    no_snapshot_load: bool = True
    no_snapshot_save: bool = True
    dns_server: str = "127.0.0.1" # overwritten by config but ideally the ipv6 should also be hardcoded
    extra_args: tuple[str, ...] = ()
    boot_timeout_seconds: float = 300.0
    adb_timeout_seconds: float = 120.0

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "EmulatorSpec":
        return EmulatorSpec(
            avd_name=str(data["avd_name"]).strip(),
            emulator_binary=str(data.get("emulator_binary", "emulator")).strip(),
            adb_binary=str(data.get("adb_binary", "adb")).strip(),
            wipe_data=bool(data.get("wipe_data", True)),
            no_snapshot_load=bool(data.get("no_snapshot_load", True)),
            no_snapshot_save=bool(data.get("no_snapshot_save", True)),
            dns_server=str(data.get("dns_server", "127.0.0.1")).strip(),
            extra_args=tuple(str(x) for x in (data.get("extra_args") or [])),
            boot_timeout_seconds=float(data.get("boot_timeout_seconds", 300.0)),
            adb_timeout_seconds=float(data.get("adb_timeout_seconds", 120.0)),
        )

@dataclass(frozen=True)
class DnsProxySpec:
    binary: str = "dnsproxy"
    listen_ip: str = "127.0.0.1" #again same as above
    listen_port: int = 53
    command_template: Optional[list[str]] = None
    log_level: str = "info"
    log_file: Optional[str] = None
    log_regex: Optional[str] = None
    event_regex: Optional[str] = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "DnsProxySpec":
        cmd = data.get("command_template")
        if cmd is not None:
            cmd = [str(x) for x in cmd]
        return DnsProxySpec(
            binary=str(data.get("binary", "dnsproxy")).strip(),
            listen_ip=str(data.get("listen_ip", "127.0.0.1")).strip(),
            listen_port=int(data.get("listen_port", 53)),
            command_template=cmd,
            log_level=str(data.get("log_level", "info")).strip(),
            log_file=data.get("log_file"),
            log_regex=data.get("log_regex"),
            event_regex=data.get("event_regex"),
        )


@dataclass(frozen=True)
class RunConfig:
    base_dir: Path
    output_dir: Path
    auth_user_pass_file: Path
    ovpn_dir: Path
    openvpn_command: tuple[str, ...]
    gateway_ip: str
    ping_binary: str = "ping"
    curl_binary: str = "curl"
    retry_count: int = 2
    cool_down_seconds: float = 2.0
    tunnel_ready_timeout_seconds: float = 120.0
    ping_count: int = 10
    ping_timeout_seconds: float = 1.0
    export_csv: bool = True
    random_seed: int = 42
    repetitions_per_vantage: int = 3
    protocols: dict[str, ProtocolSpec] | None = None
    apps: list[AppSpec] | None = None
    emulator: EmulatorSpec | None = None
    dnsproxy: DnsProxySpec | None = None
    protocols_per_run: Optional[list[str]] = None
    app_idle_gap_seconds: float = 15.0

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RunConfig":
        base_dir = Path(data.get("base_dir", ".")).expanduser()
        output_dir = Path(data["output_dir"]).expanduser()
        auth_user_pass_file = Path(data["auth_user_pass_file"]).expanduser()
        ovpn_dir = Path(data["ovpn_dir"]).expanduser()
        openvpn_command = tuple(str(x) for x in data.get("openvpn_command", ["sudo", "openvpn"]))
        gateway_ip = str(data.get("gateway_ip", "10.100.0.1"))

        protocols_data = data.get("protocols") or {}
        if not protocols_data:
            raise MeasurementError("Config must include a non-empty 'protocols' mapping.")
        protocols = {name.lower(): ProtocolSpec.from_dict(name, spec) for name, spec in protocols_data.items()}

        apps_raw = data.get("apps")
        apps: list[AppSpec]
        if apps_raw:
            apps = [AppSpec.from_dict(app, fallback_name=f"app_{idx+1}") for idx, app in enumerate(apps_raw)]
        elif "app" in data:
            apps = [AppSpec.from_dict(data["app"], fallback_name="app_1")]
        else:
            raise MeasurementError("Config must include either an 'apps' list or a legacy 'app' section.")

        emulator = EmulatorSpec.from_dict(data["emulator"]) if "emulator" in data else None
        dnsproxy = DnsProxySpec.from_dict(data["dnsproxy"]) if "dnsproxy" in data else None

        return RunConfig(
            base_dir=base_dir,
            output_dir=output_dir,
            auth_user_pass_file=auth_user_pass_file,
            ovpn_dir=ovpn_dir,
            openvpn_command=openvpn_command,
            gateway_ip=gateway_ip,
            ping_binary=str(data.get("ping_binary", "ping")),
            curl_binary=str(data.get("curl_binary", "curl")),
            retry_count=int(data.get("retry_count", 2)),
            cool_down_seconds=float(data.get("cool_down_seconds", 2.0)),
            tunnel_ready_timeout_seconds=float(data.get("tunnel_ready_timeout_seconds", 120.0)),
            ping_count=int(data.get("ping_count", 10)),
            ping_timeout_seconds=float(data.get("ping_timeout_seconds", 1.0)),
            export_csv=bool(data.get("export_csv", True)),
            random_seed=int(data.get("random_seed", 42)),
            repetitions_per_vantage=int(data.get("repetitions_per_vantage", 3)),
            protocols=protocols,
            apps=apps,
            emulator=emulator,
            dnsproxy=dnsproxy,
            protocols_per_run=[str(x).lower() for x in data.get("protocols_per_run")] if data.get("protocols_per_run") else None,
            app_idle_gap_seconds=float(data.get("app_idle_gap_seconds", 15.0)),
        )


class MeasurementStore:
    def __init__(self, db_path: Path) -> None:
        ensure_dir(db_path.parent)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vpn_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                vantage_id TEXT NOT NULL,
                ovpn_file TEXT NOT NULL,
                status TEXT NOT NULL,
                tunnel_rtt_json TEXT,
                tunnel_avg_ms REAL,
                tunnel_min_ms REAL,
                tunnel_max_ms REAL,
                tunnel_mdev_ms REAL,
                notes TEXT,
                exit_ip TEXT,
                vpn_connect_time_ms REAL
            );

            CREATE TABLE IF NOT EXISTS app_measurements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                vpn_session_id INTEGER NOT NULL,
                vantage_id TEXT NOT NULL,
                country_code TEXT,
                repetition INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                app_index INTEGER NOT NULL,
                app_name TEXT NOT NULL,
                ovpn_file TEXT NOT NULL,
                app_package TEXT NOT NULL,
                app_activity TEXT NOT NULL,
                startup_total_ms REAL,
                startup_this_ms REAL,
                startup_wait_ms REAL,
                time_to_ready_ms REAL,
                time_to_first_dns_ms REAL,
                time_to_last_dns_ms REAL,
                dns_query_count INTEGER DEFAULT 0,
                dns_answer_count INTEGER DEFAULT 0,
                dns_unique_hostnames INTEGER DEFAULT 0,
                dns_a_count INTEGER DEFAULT 0,
                dns_aaaa_count INTEGER DEFAULT 0,
                dns_https_count INTEGER DEFAULT 0,
                dns_svcb_count INTEGER DEFAULT 0,
                dns_cname_count INTEGER DEFAULT 0,
                dns_nxdomain_count INTEGER DEFAULT 0,
                dns_other_count INTEGER DEFAULT 0,
                app_launch_rc INTEGER,
                ready_rc INTEGER,
                emulator_boot_ms REAL,
                vpn_exit_ip TEXT,
                tunnel_avg_ms REAL,
                tunnel_min_ms REAL,
                tunnel_max_ms REAL,
                tunnel_mdev_ms REAL,
                dnslog_path TEXT,
                raw_start_output TEXT,
                notes TEXT,
                UNIQUE(vantage_id, repetition, protocol, app_index, app_package, app_activity)
            );

            CREATE TABLE IF NOT EXISTS dns_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                measurement_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                timestamp_ms REAL,
                qname TEXT,
                qtype TEXT,
                rcode TEXT,
                cached INTEGER,
                latency_ms REAL,
                is_answer INTEGER,
                raw_line TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_app_measurements_vantage
                ON app_measurements(vantage_id, protocol, repetition);

            CREATE INDEX IF NOT EXISTS idx_dns_events_measurement
                ON dns_events(measurement_id);
            """
        )
        self.conn.commit()

    def start_vpn_session(self, vantage_id: str, ovpn_file: str) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO vpn_sessions(created_at, vantage_id, ovpn_file, status)
            VALUES (?, ?, ?, ?)
            """,
            (utc_now(), vantage_id, ovpn_file, "starting"),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_vpn_session(self, session_id: int, *, status: str, tunnel_rtt: Optional[dict[str, float]] = None, notes: Optional[str] = None, exit_ip: Optional[str] = None, vpn_connect_time_ms: Optional[float] = None) -> None:
        avg = tunnel_rtt.get("avg") if tunnel_rtt else None
        mn = tunnel_rtt.get("min") if tunnel_rtt else None
        mx = tunnel_rtt.get("max") if tunnel_rtt else None
        mdev = tunnel_rtt.get("mdev") if tunnel_rtt else None
        self.conn.execute(
            """
            UPDATE vpn_sessions
            SET status = ?,
                tunnel_rtt_json = ?,
                tunnel_avg_ms = ?,
                tunnel_min_ms = ?,
                tunnel_max_ms = ?,
                tunnel_mdev_ms = ?,
                notes = ?,
                exit_ip = ?,
                vpn_connect_time_ms = ?
            WHERE id = ?
            """,
            (
                status,
                safe_json(tunnel_rtt) if tunnel_rtt is not None else None,
                avg,
                mn,
                mx,
                mdev,
                notes,
                exit_ip,
                vpn_connect_time_ms,
                session_id,
            ),
        )
        self.conn.commit()

    def insert_app_measurement(self, row: dict[str, Any]) -> int:
        cols = list(row.keys())
        values = [row[k] for k in cols]
        sql = f"""
            INSERT INTO app_measurements({",".join(cols)})
            VALUES ({",".join(["?"] * len(cols))})
        """
        cur = self.conn.execute(sql, values)
        self.conn.commit()
        return int(cur.lastrowid)

    def update_app_measurement(self, measurement_id: int, row: dict[str, Any]) -> None:
        cols = list(row.keys())
        values = [row[k] for k in cols]
        sql = f"""
            UPDATE app_measurements
            SET {", ".join([f"{c}=?" for c in cols])}
            WHERE id = ?
        """
        self.conn.execute(sql, values + [measurement_id])
        self.conn.commit()

    def insert_dns_event(self, row: dict[str, Any]) -> None:
        cols = list(row.keys())
        values = [row[k] for k in cols]
        sql = f"""
            INSERT INTO dns_events({",".join(cols)})
            VALUES ({",".join(["?"] * len(cols))})
        """
        self.conn.execute(sql, values)
        self.conn.commit()
    #Again, csv not used: delete
    def export_csv(self, path: Path) -> None:
        ensure_dir(path.parent)
        rows = self.conn.execute(
            """
            SELECT *
            FROM app_measurements
            ORDER BY vantage_id, protocol, repetition, app_index
            """
        ).fetchall()
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow([row[k] for k in row.keys()])

    def export_dns_csv(self, path: Path) -> None:
        ensure_dir(path.parent)
        rows = self.conn.execute(
            """
            SELECT *
            FROM dns_events
            ORDER BY measurement_id, id
            """
        ).fetchall()
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow([row[k] for k in row.keys()])


class ProcessWrapper:
    def __init__(self, proc: subprocess.Popen[str], name: str) -> None:
        self.proc = proc
        self.name = name

    def terminate(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=5)
            except Exception:
                pass

class DnsProxyEvent:
    def __init__(self,*,seen_monotonic: float,timestamp_ms: Optional[float],qname: Optional[str],qtype: Optional[str],rcode: Optional[str],cached: Optional[int],latency_ms: Optional[float],is_answer: bool,raw_line: str) -> None:
        self.seen_monotonic = seen_monotonic
        self.timestamp_ms = timestamp_ms
        self.qname = qname
        self.qtype = qtype
        self.rcode = rcode
        self.cached = cached
        self.latency_ms = latency_ms
        self.is_answer = is_answer
        self.raw_line = raw_line

class DnsProxyRunner:
    def __init__(self, spec: DnsProxySpec, context: dict[str, str], log_dir: Path) -> None:
        self.spec = spec
        self.context = context
        self.log_dir = log_dir
        self.proc: Optional[subprocess.Popen[str]] = None
        self.log_path = log_dir / f"dnsproxy-{uuid.uuid4().hex}.log"
        self.log_fh = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.events: list[DnsProxyEvent] = []
        self.raw_lines: list[str] = []
        self._start_monotonic: Optional[float] = None
    #replace placeholder
    def _render(self, parts: list[str]) -> list[str]:
        return [p.format(**self.context) for p in parts]

    def _build_command(self) -> list[str]:
        if self.spec.command_template:
            argv = self._render(self.spec.command_template)
            if "--upstream" not in argv and "-u" not in argv:
                argv += ["--upstream", self.context["upstream"]]
            if self.context.get("sni") and "--tls-hostname" not in argv: #?
                argv += ["--tls-hostname", self.context["sni"]]
            if self.spec.log_file and "--log-file" not in argv:
                argv += ["--log-file", self.spec.log_file.format(**self.context)]
            extra = self.context.get("extra_args", "").strip()
            if extra:
                argv.extend(extra.split())
            return argv

        argv = [
            self.spec.binary,
            "--listen",
            self.spec.listen_ip,
            "--port",
            str(self.spec.listen_port),
            "--upstream",
            self.context["upstream"],
            "--log-level",
            self.spec.log_level,
        ]
        if self.context.get("sni"):
            argv += ["--tls-hostname", self.context["sni"]]
        if self.spec.log_file:
            argv += ["--log-file", self.spec.log_file.format(**self.context)]
        extra = self.context.get("extra_args", "").strip()
        if extra:
            argv.extend(extra.split())
        return argv

    def start(self) -> None:
        ensure_dir(self.log_dir)
        argv = self._build_command()
        LOG.info("Starting DNS proxy: %s", " ".join(argv))
        self._start_monotonic = time.monotonic()
        self.proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if self.proc.stdout is None:
            raise MeasurementError("dnsproxy stdout unavailable")
        self.log_fh = self.log_path.open("w", encoding="utf-8")

        def _pump() -> None:
            try:
                while not self._stop.is_set():
                    line = self.proc.stdout.readline()
                    if not line:
                        if self.proc.poll() is not None:
                            break
                        time.sleep(0.05)
                        continue
                    if self.log_fh is not None:
                        self.log_fh.write(line)
                        self.log_fh.flush()
                    self.raw_lines.append(line)
                    event = self.parse_event(line)
                    if event is not None:
                        self.events.append(event)
            finally:
                try:
                    if self.log_fh is not None:
                        self.log_fh.flush()
                        self.log_fh.close()
                except Exception:
                    pass

        self._thread = threading.Thread(target=_pump, name="dnsproxy-capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self._thread:
            self._thread.join(timeout=5)

    def degradation_reason(self, start_line_index: int) -> Optional[str]:
        if start_line_index < 0:
            start_line_index = 0
        recent_lines = self.raw_lines[start_line_index:]
        if not recent_lines:
            return None

        recent = "".join(recent_lines)
        # as observed in dnsproxy output
        bad_match = re.search(
            r"(i/o timeout|network is unreachable|no route to host|connection refused)",
            recent,
            re.IGNORECASE,
        )
        if not bad_match:
            return None
            
        if re.search(r"connectivitycheck\.gstatic\.com", recent, re.IGNORECASE):
            return "connectivitycheck traffic plus DNS failure"

        return bad_match.group(1)

    def parse_event(self, line: str) -> Optional[DnsProxyEvent]:
        seen_monotonic = time.monotonic()
        regex = self.spec.event_regex or self.spec.log_regex
        if regex:
            m = re.search(regex, line)
            if not m:
                return None
            gd = m.groupdict()
            return DnsProxyEvent(
                seen_monotonic=seen_monotonic,
                timestamp_ms=parse_float(gd.get("timestamp_ms", "")) if gd.get("timestamp_ms") else None,
                qname=gd.get("qname"),
                qtype=gd.get("qtype"),
                rcode=gd.get("rcode"),
                cached=parse_int(gd.get("cached", "")) if gd.get("cached") else None,
                latency_ms=parse_float(gd.get("latency_ms", "")) if gd.get("latency_ms") else None,
                is_answer=_parse_boolish(gd.get("is_answer")) if gd.get("is_answer") is not None else _heuristic_is_answer(line),
                raw_line=line.rstrip("\n"),
            )

        qname_m = re.search(r"\bqname=([^\s,]+)", line, re.IGNORECASE)
        qtype_m = re.search(r"\bqtype=([A-Za-z0-9]+)", line, re.IGNORECASE)
        if not (qname_m and qtype_m):
            return None

        rcode_m = re.search(r"\brcode=([A-Z]+)", line, re.IGNORECASE)
        cached_m = re.search(r"\bcached=([01])", line, re.IGNORECASE)
        latency_m = re.search(r"\blatency_ms=([0-9.]+)", line, re.IGNORECASE)

        return DnsProxyEvent(
            seen_monotonic=seen_monotonic,
            timestamp_ms=None,
            qname=qname_m.group(1),
            qtype=qtype_m.group(1).upper(),
            rcode=rcode_m.group(1).upper() if rcode_m else None,
            cached=parse_int(cached_m.group(1)) if cached_m else None,
            latency_ms=parse_float(latency_m.group(1)) if latency_m else None,
            is_answer=_heuristic_is_answer(line),
            raw_line=line.rstrip("\n"),
        )

    def wait_for_idle(
        self,
        *,
        start_index: int,
        start_line_index: int,
        idle_gap_seconds: float,
        timeout_seconds: float,
    ) -> tuple[list[DnsProxyEvent], Optional[DnsProxyEvent]]:
        deadline = time.monotonic() + timeout_seconds
        last_progress = time.monotonic()
        last_event: Optional[DnsProxyEvent] = None
        seen_any = False

        while time.monotonic() < deadline:
            degradation_reason = self.degradation_reason(start_line_index)
            if degradation_reason:
                raise NetworkDegradationError(degradation_reason)

            events = self.events[start_index:]
            if events:
                seen_any = True
                last_event = self._last_answer_or_event(events)
                idle_for = time.monotonic() - last_event.seen_monotonic
                if idle_for >= idle_gap_seconds:
                    return events, last_event
                last_progress = time.monotonic()
            else:
                if time.monotonic() - last_progress > 1.0:
                    last_progress = time.monotonic()
            time.sleep(0.25)

        events = self.events[start_index:]
        if events:
            last_event = self._last_answer_or_event(events)
        if not seen_any:
            return [], None
        raise DnsSilenceTimeoutError(
            f"Timed out waiting for {idle_gap_seconds:.1f}s of DNS silence after app launch."
        )

    @staticmethod
    def _last_answer_or_event(events: list[DnsProxyEvent]) -> DnsProxyEvent:
        answer_events = [ev for ev in events if ev.is_answer]
        return answer_events[-1] if answer_events else events[-1]


def _heuristic_is_answer(line: str) -> bool:
    return bool(re.search(r"\b(answer|response|reply)\b", line, re.IGNORECASE))


def _parse_boolish(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y", "answer", "response"}


class ADB:
    def __init__(self, adb_binary: str, timeout_seconds: float = 120.0) -> None:
        self.adb_binary = adb_binary
        self.timeout_seconds = timeout_seconds

    def run(self, args: list[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess[str]:
        return run_command([self.adb_binary] + args, timeout=timeout or self.timeout_seconds)

    def wait_for_device(self) -> None:
        self.run(["wait-for-device"], timeout=self.timeout_seconds)

    def shell(self, command: str, timeout: Optional[float] = None) -> subprocess.CompletedProcess[str]:
        return self.run(["shell", command], timeout=timeout)

    def shell_text(self, command: str, timeout: Optional[float] = None) -> str:
        proc = self.shell(command, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")

    def force_stop(self, package: str) -> None:
        self.shell(f"am force-stop {package}")

    def clear_package(self, package: str) -> None:
        self.shell(f"pm clear {package}")

    def start_activity(self, package: str, app: AppSpec) -> str:
        argv = ["am", "start", "-W", "-n", f"{package}/{app.launch_activity}"]
        if app.launch_action:
            argv.extend(["-a", app.launch_action])
        if app.launch_category:
            argv.extend(["-c", app.launch_category])
        argv.extend(app.launch_extra_args)
        proc = self.run(["shell"] + argv, timeout=max(self.timeout_seconds, app.launch_timeout_seconds))
        return (proc.stdout or "") + (proc.stderr or "")

    def settings_put_global(self, key: str, value: str) -> None:
        self.shell(f"settings put global {key} {value}")


class EmulatorRunner:
    def __init__(self, spec: EmulatorSpec) -> None:
        self.spec = spec
        self.proc: Optional[subprocess.Popen[str]] = None
        self.start_time: Optional[float] = None

    def start(self) -> None:
        argv = [self.spec.emulator_binary, "-avd", self.spec.avd_name, "-dns-server", self.spec.dns_server]
        if self.spec.wipe_data:
            argv.append("-wipe-data")
        if self.spec.no_snapshot_load:
            argv.append("-no-snapshot-load")
        if self.spec.no_snapshot_save:
            argv.append("-no-snapshot-save")
        argv.extend(self.spec.extra_args)
        LOG.info("Starting emulator: %s", " ".join(argv))
        self.start_time = time.monotonic()
        self.proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    def wait_for_boot(self, adb: ADB) -> float:
        if self.start_time is None:
            raise MeasurementError("Emulator not started")
        deadline = time.monotonic() + self.spec.boot_timeout_seconds
        last = ""
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                if self.proc.stdout:
                    last = self.proc.stdout.read() or ""
                raise MeasurementError(f"Emulator exited early:\n{last}")
            proc = adb.run(["shell", "getprop", "sys.boot_completed"], timeout=10.0)
            out = (proc.stdout or "").strip()
            if out == "1":
                time.sleep(5.0)
                return (time.monotonic() - self.start_time) * 1000.0
            time.sleep(2.0)
        raise MeasurementError("Emulator boot timed out")

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=15)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


def detect_country_from_ovpn(path: Path) -> Optional[str]:
    m = re.match(r"^([a-z]{2})(\d+)", path.stem, re.IGNORECASE)
    return m.group(1).lower() if m else None


def group_ovpn_files_by_country(ovpn_dir: Path) -> dict[str, list[Path]]:
    if not ovpn_dir.is_dir():
        raise MeasurementError(f"OVPN directory not found: {ovpn_dir}")
    files = sorted(p for p in ovpn_dir.iterdir() if p.suffix == ".ovpn" and p.is_file())
    if not files:
        raise MeasurementError(f"Noovpn files found in {ovpn_dir}")
    groups: dict[str, list[Path]] = {}
    for f in files:
        c = detect_country_from_ovpn(f)
        if c is None:
            continue
        groups.setdefault(c, []).append(f)
    rng = random.Random(42)
    for members in groups.values():
        rng.shuffle(members)
    return groups


def validate_inputs(cfg: RunConfig) -> None:
    if not cfg.auth_user_pass_file.is_file():
        raise MeasurementError(f"Auth credential file not found: {cfg.auth_user_pass_file}")
    if not cfg.ovpn_dir.is_dir():
        raise MeasurementError(f"OVPN directory not found: {cfg.ovpn_dir}")
    ensure_dir(cfg.output_dir)
    which_or_die(cfg.ping_binary)
    which_or_die(cfg.curl_binary)
    for binary in cfg.openvpn_command:
        if binary == "sudo":
            continue
        if "/" not in binary:
            which_or_die(binary)
    if cfg.emulator is None:
        raise MeasurementError("Config must include emulator section")
    if cfg.dnsproxy is None:
        raise MeasurementError("Config must include dnsproxy section")
    if cfg.protocols is None or not cfg.protocols:
        raise MeasurementError("Config must include protocols section")
    if cfg.apps is None or not cfg.apps:
        raise MeasurementError("Config must include at least one app")

def setup_signal_handlers() -> None:
    def _handler(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"Interrupted by signal {signum}")

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

def start_openvpn(openvpn_command: tuple[str, ...], ovpn_file: Path, auth_file: Path) -> subprocess.Popen[str]:
    argv = list(openvpn_command) + ["--config", str(ovpn_file), "--auth-user-pass", str(auth_file)]
    LOG.info("Starting OpenVPN: %s", " ".join(argv))
    return subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

def stop_process(proc: Optional[subprocess.Popen[str]]) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass

def wait_for_openvpn_ready(proc: subprocess.Popen[str], timeout_seconds: float) -> str:
    if proc.stdout is None:
        raise MeasurementError("OpenVPN stdout unavailable")
    deadline = time.monotonic() + timeout_seconds
    seen: list[str] = []
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if line:
            seen.append(line)
            if "Initialization Sequence Completed" in line:
                return "".join(seen)
        else:
            time.sleep(0.2)
    if proc.poll() is not None:
        seen.extend(proc.stdout.readlines() if proc.stdout else [])
        raise MeasurementError("OpenVPN exited before becoming ready:\n" + "".join(seen))
    raise MeasurementError("OpenVPN did not become ready within timeout")


def measure_tunnel_latency(ping_binary: str, gateway_ip: str, ping_count: int, ping_timeout_seconds: float) -> dict[str, float]:
    proc = run_command(
        [
            ping_binary,
            "-c",
            str(ping_count),
            "-q",
            "-W",
            str(int(max(1, round(ping_timeout_seconds)))),
            gateway_ip,
        ],
        timeout=max(5.0, ping_count * (ping_timeout_seconds + 1.0)),
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise MeasurementError(f"Ping failed for {gateway_ip}:\n{output}")
    rtt = parse_ping_rtt(output)
    if rtt is None:
        raise MeasurementError(f"Could not parse ping output:\n{output}")
    return rtt


def get_exit_ip(curl_binary: str) -> Optional[str]:
    try:
        proc = run_command([curl_binary, "-4", "-s", "https://api.ipify.org"], timeout=15.0)
        if proc.returncode == 0:
            ip = (proc.stdout or "").strip()
            if ip:
                return ip
    except Exception:
        pass
    return None

def extract_start_metrics(raw: str) -> dict[str, Optional[float]]:
    result: dict[str, Optional[float]] = {
        "startup_this_ms": None,
        "startup_total_ms": None,
        "startup_wait_ms": None,
    }
    mapping = {
        "ThisTime": "startup_this_ms",
        "TotalTime": "startup_total_ms",
        "WaitTime": "startup_wait_ms",
    }
    for key, out_key in mapping.items():
        m = re.search(rf"^{key}:\s*([0-9]+(?:\.[0-9]+)?)\s*$", raw, re.MULTILINE)
        if m:
            result[out_key] = float(m.group(1))
    return result

def build_dnsproxy_context(protocol: ProtocolSpec) -> dict[str, str]:
    upstream = protocol.upstream
    if protocol.port is not None:
        upstream = f"{upstream}:{protocol.port}"
    return {
        "protocol": protocol.name,
        "upstream": upstream,
        "upstream_host": protocol.upstream,
        "upstream_port": "" if protocol.port is None else str(protocol.port),
        "port": "" if protocol.port is None else str(protocol.port),
        "sni": "" if protocol.sni is None else protocol.sni,
        "extra_args": " ".join(protocol.extra_args),
    }

def summarize_dns_events(events: list[DnsProxyEvent], launch_t0: float) -> tuple[int, int, dict[str, int], Optional[float], Optional[float]]:
    total = len(events)
    unique_hostnames: set[str] = set()
    counts = {
        "A": 0,
        "AAAA": 0,
        "HTTPS": 0,
        "SVCB": 0,
        "CNAME": 0,
        "NXDOMAIN": 0,
        "OTHER": 0,
    }
    first_dns_ms: Optional[float] = None
    last_dns_ms: Optional[float] = None

    for ev in events:
        if ev.qname:
            unique_hostnames.add(ev.qname.lower())
        qtype = (ev.qtype or "").upper()
        if qtype in counts:
            counts[qtype] += 1
        else:
            counts["OTHER"] += 1
        rel_ms = (ev.seen_monotonic - launch_t0) * 1000.0
        if first_dns_ms is None:
            first_dns_ms = rel_ms
        last_dns_ms = rel_ms

    return total, len(unique_hostnames), counts, first_dns_ms, last_dns_ms

def run_single_app_measurement(
    *,
    store: MeasurementStore,
    cfg: RunConfig,
    adb: ADB,
    dnsproxy: DnsProxyRunner,
    ovpn_file: Path,
    vantage_id: str,
    country_code: Optional[str],
    session_id: int,
    protocol_name: str,
    protocol: ProtocolSpec,
    repetition: int,
    app_index: int,
    app: AppSpec,
    vpn_exit_ip: Optional[str],
    tunnel_rtt: Optional[dict[str, float]],
    vpn_connect_time_ms: Optional[float],
    emulator_boot_ms: Optional[float],
) -> None:
    log_dir = cfg.output_dir / "logs" / vantage_id / protocol_name / f"rep-{repetition}" / f"app-{app_index}-{app.name}"
    ensure_dir(log_dir)

    measurement_id = store.insert_app_measurement(
        {
            "created_at": utc_now(),
            "vpn_session_id": session_id,
            "vantage_id": vantage_id,
            "country_code": country_code,
            "repetition": repetition,
            "protocol": protocol_name,
            "app_index": app_index,
            "app_name": app.name,
            "ovpn_file": str(ovpn_file),
            "app_package": app.package,
            "app_activity": app.launch_activity,
            "dnslog_path": str(dnsproxy.log_path),
            "notes": None,
        }
    )

    start_rc: Optional[int] = None
    ready_rc: Optional[int] = None
    raw_start = ""
    time_to_ready_ms: Optional[float] = None
    notes: Optional[str] = None
    startup_metrics: dict[str, Optional[float]] = {
        "startup_total_ms": None,
        "startup_this_ms": None,
        "startup_wait_ms": None,
    }

    try:
        if app.force_stop_before_launch:
            adb.force_stop(app.package)
        if app.clear_data:
            adb.clear_package(app.package)

        start_index = len(dnsproxy.events)
        start_line_index = len(dnsproxy.raw_lines)
        launch_t0 = time.monotonic()
        raw_start = adb.start_activity(app.package, app)
        start_rc = 0 if raw_start.strip() else 1
        startup_metrics = extract_start_metrics(raw_start)

        events, last_event = dnsproxy.wait_for_idle(
            start_index=start_index,
            start_line_index=start_line_index,
            idle_gap_seconds=cfg.app_idle_gap_seconds,
            timeout_seconds=app.ready_timeout_seconds,
        )

        if last_event is not None:
            time_to_ready_ms = max(0.0, (last_event.seen_monotonic - launch_t0) * 1000.0)
            ready_rc = 0
            #close app once measurements are collected
            adb.force_stop(app.package)
        else:
            ready_rc = 1

        total, unique_count, counts, first_dns_ms, last_dns_ms = summarize_dns_events(events, launch_t0)
        if ready_rc != 0 and not events:
            notes = "No DNS events captured during app run"

        row_update = {
            "startup_total_ms": startup_metrics["startup_total_ms"],
            "startup_this_ms": startup_metrics["startup_this_ms"],
            "startup_wait_ms": startup_metrics["startup_wait_ms"],
            "time_to_ready_ms": time_to_ready_ms,
            "time_to_first_dns_ms": first_dns_ms,
            "time_to_last_dns_ms": last_dns_ms,
            "dns_query_count": total,
            "dns_answer_count": sum(1 for ev in events if ev.is_answer),
            "dns_unique_hostnames": unique_count,
            "dns_a_count": counts["A"],
            "dns_aaaa_count": counts["AAAA"],
            "dns_https_count": counts["HTTPS"],
            "dns_svcb_count": counts["SVCB"],
            "dns_cname_count": counts["CNAME"],
            "dns_nxdomain_count": counts["NXDOMAIN"],
            "dns_other_count": counts["OTHER"],
            "app_launch_rc": start_rc,
            "ready_rc": ready_rc,
            "emulator_boot_ms": emulator_boot_ms,
            "vpn_exit_ip": vpn_exit_ip,
            "tunnel_avg_ms": tunnel_rtt["avg"] if tunnel_rtt else None,
            "tunnel_min_ms": tunnel_rtt["min"] if tunnel_rtt else None,
            "tunnel_max_ms": tunnel_rtt["max"] if tunnel_rtt else None,
            "tunnel_mdev_ms": tunnel_rtt["mdev"] if tunnel_rtt else None,
            "raw_start_output": raw_start,
            "notes": notes,
        }
        store.update_app_measurement(measurement_id, row_update)

        for ev in events:
            store.insert_dns_event(
                {
                    "measurement_id": measurement_id,
                    "created_at": utc_now(),
                    "timestamp_ms": ev.timestamp_ms,
                    "qname": ev.qname,
                    "qtype": ev.qtype,
                    "rcode": ev.rcode,
                    "cached": ev.cached,
                    "latency_ms": ev.latency_ms,
                    "is_answer": 1 if ev.is_answer else 0,
                    "raw_line": ev.raw_line,
                }
            )

    except Exception as exc:
        store.update_app_measurement(
            measurement_id,
            {
                "notes": str(exc),
                "app_launch_rc": 1 if start_rc is None else start_rc,
                "ready_rc": 1 if ready_rc is None else ready_rc,
                "raw_start_output": raw_start,
            },
        )
        raise


def run_single_repetition(
    *,
    store: MeasurementStore,
    cfg: RunConfig,
    adb: ADB,
    ovpn_file: Path,
    vantage_id: str,
    country_code: Optional[str],
    session_id: int,
    protocol_name: str,
    protocol: ProtocolSpec,
    repetition: int,
    vpn_exit_ip: Optional[str],
    tunnel_rtt: Optional[dict[str, float]],
    vpn_connect_time_ms: Optional[float],
) -> None:
    emulator = EmulatorRunner(cfg.emulator)
    emulator.start()
    dnsproxy: Optional[DnsProxyRunner] = None
    try:
        emulator_boot_ms = emulator.wait_for_boot(adb)
        LOG.info(
            "[%s] Emulator booted in %.1f ms for protocol=%s repetition=%d/%d",
            vantage_id,
            emulator_boot_ms,
            protocol_name,
            repetition + 1,
            cfg.repetitions_per_vantage,
        )

        adb.settings_put_global("private_dns_mode", "off")

        dnsproxy = DnsProxyRunner(
            cfg.dnsproxy,
            context=build_dnsproxy_context(protocol),
            log_dir=cfg.output_dir / "logs" / vantage_id / protocol_name / f"rep-{repetition}" / "dnsproxy",
        )
        dnsproxy.start()

        for app_index, app in enumerate(cfg.apps, start=1):
            LOG.info(
                "[%s] protocol=%s repetition=%d app=%d/%d (%s)",
                vantage_id,
                protocol_name,
                repetition + 1,
                app_index,
                len(cfg.apps),
                app.name,
            )
            run_single_app_measurement(
                store=store,
                cfg=cfg,
                adb=adb,
                dnsproxy=dnsproxy,
                ovpn_file=ovpn_file,
                vantage_id=vantage_id,
                country_code=country_code,
                session_id=session_id,
                protocol_name=protocol_name,
                protocol=protocol,
                repetition=repetition,
                app_index=app_index,
                app=app,
                vpn_exit_ip=vpn_exit_ip,
                tunnel_rtt=tunnel_rtt,
                vpn_connect_time_ms=vpn_connect_time_ms,
                emulator_boot_ms=emulator_boot_ms,
            )
            if app_index < len(cfg.apps):
                time.sleep(10)

    finally:
        if dnsproxy is not None:
            dnsproxy.stop()
        emulator.stop()


def run_one_vantage(*, store: MeasurementStore, cfg: RunConfig, ovpn_file: Path, country_code: Optional[str]) -> None:
    vantage_id = ovpn_file.stem
    session_id = store.start_vpn_session(vantage_id, str(ovpn_file))
    openvpn_proc: Optional[subprocess.Popen[str]] = None
    tunnel_rtt: Optional[dict[str, float]] = None
    exit_ip: Optional[str] = None
    vpn_connect_time_ms: Optional[float] = None
    try:
        openvpn_proc = start_openvpn(cfg.openvpn_command, ovpn_file, cfg.auth_user_pass_file)
        vpn_start = time.monotonic()
        wait_for_openvpn_ready(openvpn_proc, cfg.tunnel_ready_timeout_seconds)
        vpn_connect_time_ms = (time.monotonic() - vpn_start) * 1000.0
        tunnel_rtt = measure_tunnel_latency(
            cfg.ping_binary,
            cfg.gateway_ip,
            cfg.ping_count,
            cfg.ping_timeout_seconds,
        )
        exit_ip = get_exit_ip(cfg.curl_binary)
        if not exit_ip:
            raise MeasurementError("VPN connected but could not resolve exit IP")
        store.finish_vpn_session(
            session_id,
            status="ready",
            tunnel_rtt=tunnel_rtt,
            exit_ip=exit_ip,
            vpn_connect_time_ms=vpn_connect_time_ms,
        )

        adb = ADB(cfg.emulator.adb_binary, timeout_seconds=cfg.emulator.adb_timeout_seconds)
        #adb.wait_for_device()

        protocols = cfg.protocols_per_run or list(cfg.protocols.keys())
        for protocol_name in protocols:
            protocol_name = protocol_name.lower()
            if protocol_name not in cfg.protocols:
                raise MeasurementError(f"Unknown protocol in protocols_per_run: {protocol_name}")
            protocol = cfg.protocols[protocol_name]
            
            protocol_ok = True

            for repetition in range(cfg.repetitions_per_vantage):
                try:
                    run_single_repetition(
                        store=store,
                        cfg=cfg,
                        adb=adb,
                        ovpn_file=ovpn_file,
                        vantage_id=vantage_id,
                        country_code=country_code,
                        session_id=session_id,
                        protocol_name=protocol_name,
                        protocol=protocol,
                        repetition=repetition,
                        vpn_exit_ip=exit_ip,
                        tunnel_rtt=tunnel_rtt,
                        vpn_connect_time_ms=vpn_connect_time_ms,
                    )
                except DnsSilenceTimeoutError as exc:
                    LOG.warning("[%s] protocol=%s repetition=%d failed: %s", vantage_id, protocol_name, repetition + 1, exc,)
                    protocol_ok = False
                    break
            if not protocol_ok:
                continue

        store.finish_vpn_session(
            session_id,
            status="completed",
            tunnel_rtt=tunnel_rtt,
            exit_ip=exit_ip,
            vpn_connect_time_ms=vpn_connect_time_ms,
        )
    except NetworkDegradationError as exc:
        store.finish_vpn_session(
            session_id,
            status="skipped_degraded",
            tunnel_rtt=tunnel_rtt,
            notes=str(exc),
            exit_ip=exit_ip,
            vpn_connect_time_ms=vpn_connect_time_ms,
        )
        raise
    except Exception as exc:
        store.finish_vpn_session(
            session_id,
            status="failed",
            tunnel_rtt=tunnel_rtt,
            notes=str(exc),
            exit_ip=exit_ip,
        )
        raise
    finally:
        stop_process(openvpn_proc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Automate Android app latency measurements over VPN vantage points.")
    parser.add_argument("--config", required=True, help="Path to JSON configuration.")
    parser.add_argument("--ovpn", help="Optional path to a single ovpn file.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    args = parser.parse_args()

    setup_logging(args.verbose)
    setup_signal_handlers()

    cfg_raw = load_config(Path(args.config).expanduser())
    cfg = RunConfig.from_dict(cfg_raw)
    validate_inputs(cfg)
    ensure_dir(cfg.output_dir)

    store = MeasurementStore(cfg.output_dir / "measurements.sqlite3")
    try:
        if args.ovpn:
            cc = detect_country_from_ovpn(Path(args.ovpn).expanduser())
            try:
                run_one_vantage(
                    store=store,
                    cfg=cfg,
                    ovpn_file=Path(args.ovpn).expanduser(),
                    country_code=cc,
                )
            except NetworkDegradationError as exc:
                LOG.warning("Skipping VPN endpoint %s due to network degradation: %s", args.ovpn, exc)
            except Exception:
                LOG.exception("Vantage point failed: %s", args.ovpn)
        else:
            grouped = group_ovpn_files_by_country(cfg.ovpn_dir)
            for country in sorted(grouped):
                LOG.info("Starting measurements for %s", country.upper())
                success = False
                for ovpn_file in grouped[country]:
                    try:
                        LOG.info("Trying VPN endpoint %s for %s", ovpn_file.name, country.upper())
                        run_one_vantage(
                            store=store,
                            cfg=cfg,
                            ovpn_file=ovpn_file,
                            country_code=country,
                        )
                        LOG.info("Successfully measured %s using %s", country.upper(), ovpn_file.name)
                        success = True
                        break
                    except NetworkDegradationError as exc:
                        LOG.warning("Skipping VPN endpoint %s due to network degradation: %s", ovpn_file.name, exc)
                        continue
                    except Exception:
                        LOG.exception("VPN endpoint failed: %s", ovpn_file.name)
                if not success:
                    LOG.error("No working VPN endpoint found for %s", country.upper())
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
