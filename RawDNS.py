from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import json
import logging
import os
import random
import re
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

LOG = logging.getLogger("dox_measurement")

KDIG_QUERY_TIME_RE = re.compile(
        r"^;;\s+FROM\s+.*?\s+in\s+(?P<value>[0-9]+(?:\.[0-9]+)?)\s*ms\s*$",
    re.IGNORECASE | re.MULTILINE,
)
PING_RTT_RE = re.compile(
    r"=\s*(?P<min>[0-9]+(?:\.[0-9]+)?)/(?P<avg>[0-9]+(?:\.[0-9]+)?)/(?P<max>[0-9]+(?:\.[0-9]+)?)/(?P<mdev>[0-9]+(?:\.[0-9]+)?)\s*ms",
    re.IGNORECASE,
)
PING_LOSS_RE = re.compile(
    r"(?P<loss>[0-9]+(?:\.[0-9]+)?)%\s+packet\s+loss",
    re.IGNORECASE,
)

class MeasurementError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

# ensure ability to create directories  
def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def which_or_die(binary: str) -> str:
    from shutil import which
    found = which(binary)
    if not found:
        raise MeasurementError(f"!! Required binary not found in PATH: {binary}")
    return found

# yaml?
def load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def protocol_display_name(protocol: str) -> str:
    protocol = protocol.lower().strip()
    mapping = {
        "do53": "Do53",
        "dot": "DoT",
        "doh": "DoH",
        "doq": "DoQ",
    }
    if protocol not in mapping:
        raise MeasurementError(f"Unsupported protocol: {protocol}")
    return mapping[protocol]


def measurement_modes() -> list[str]:
    return ["full_cold", "warm", "full_warm"]

def mode_description(mode: str) -> str:
    return {
        "full_cold": "cache-busting + new connection per query",
        "warm": "cache-busting + reused connection",
        "full_warm": "cache hit + reused connection",
    }[mode]


def generate_qname(base_domain: str, prefix: str = "dox") -> str:
    token = uuid.uuid4().hex
    return f"{prefix}-{token}.{base_domain}".rstrip(".")

def generate_qnames(base_domain: str, n: int, *, same_name: bool, prefix: str) -> list[str]:
    if n <= 0:
        raise ValueError("n isnt positive")
    if same_name: # full_warm
        qname = generate_qname(base_domain, prefix=prefix)
        return [qname] * n
    return [generate_qname(base_domain, prefix=prefix) for _ in range(n)]


def parse_kdig_query_times(output: str) -> list[float]:
    times_ms: list[float] = []
    for match in KDIG_QUERY_TIME_RE.finditer(output):
        times_ms.append(float(match.group("value")))
    return times_ms

# parse VPN ifno for logs
def parse_ping_rtt(output: str) -> Optional[dict[str, float]]:
    match = PING_RTT_RE.search(output)
    if not match:
        return None

    result = {
        k: float(match.group(k))
        for k in ("min", "avg", "max", "mdev")
    }
    loss_match = PING_LOSS_RE.search(output)
    result["loss_pct"] = (
        float(loss_match.group("loss"))
        if loss_match
        else 0.0
    )
    return result


@dataclass(frozen=True)
class ProtocolSpec:
    name: str
    server: str
    port: Optional[int] = None
    extra_args: tuple[str, ...] = ()

    @staticmethod
    def from_dict(name: str, data: dict[str, Any]) -> "ProtocolSpec": #ahja
        extra = tuple(str(x) for x in data.get("extra_args", []) or [])
        port = data.get("port")
        if port is not None:
            port = int(port)
        server = str(data["server"])
        return ProtocolSpec(name=name.lower(), server=server, port=port, extra_args=extra)

    def kdig_server_token(self) -> str:
        if self.port is None:
            return f"@{self.server}"
        return f"@{self.server}#{self.port}"

@dataclass(frozen=True)
class RunConfig:
    base_domain: str
    gateway_ip: str
    query_type: str
    samples_per_mode: int
    query_timeout_seconds: float
    ping_count: int
    ping_timeout_seconds: float
    openvpn_command: tuple[str, ...]
    auth_user_pass_file: Path
    ovpn_dir: Path
    output_dir: Path
    protocols: dict[str, ProtocolSpec]
    kdig_binary: str = "kdig"
    ping_binary: str = "ping" #hping3?
    retry_count: int = 2
    cool_down_seconds: float = 1.0
    tunnel_ready_timeout_seconds: float = 120.0
    batch_size: int = 25
    random_seed: int = 42

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RunConfig":
        base_domain = str(data["base_domain"]).strip(".")
        gateway_ip = str(data.get("gateway_ip", "10.100.0.1"))
        query_type = str(data.get("query_type", "A")).upper()
        samples_per_mode = int(data.get("samples_per_mode", 200))
        query_timeout_seconds = float(data.get("query_timeout_seconds", 4.0))
        ping_count = int(data.get("ping_count", 10))
        ping_timeout_seconds = float(data.get("ping_timeout_seconds", 1.0))
        openvpn_command = tuple(str(x) for x in data.get("openvpn_command", ["sudo", "openvpn"]))
        auth_user_pass_file = Path(data["auth_user_pass_file"]).expanduser()
        ovpn_dir = Path(data["ovpn_dir"]).expanduser()
        output_dir = Path(data["output_dir"]).expanduser()
        retry_count = int(data.get("retry_count", 2))
        cool_down_seconds = float(data.get("cool_down_seconds", 1.0))
        tunnel_ready_timeout_seconds = float(data.get("tunnel_ready_timeout_seconds", 120.0))
        batch_size = int(data.get("batch_size", 25))
        random_seed = int(data.get("random_seed", 42))

        protocols_data = data.get("protocols") or {}
        if not protocols_data:
            raise MeasurementError("protocol specs are missing from config")
        protocols = {
            name.lower(): ProtocolSpec.from_dict(name, spec)
            for name, spec in protocols_data.items()
        }
        for required in ("do53", "dot", "doh", "doq"):
            if required not in protocols:
                raise MeasurementError(f"missing protocol config: {required}")

        return RunConfig(
            base_domain=base_domain,
            gateway_ip=gateway_ip,
            query_type=query_type,
            samples_per_mode=samples_per_mode,
            query_timeout_seconds=query_timeout_seconds,
            ping_count=ping_count,
            ping_timeout_seconds=ping_timeout_seconds,
            openvpn_command=openvpn_command,
            auth_user_pass_file=auth_user_pass_file,
            ovpn_dir=ovpn_dir,
            output_dir=output_dir,
            protocols=protocols,
            retry_count=retry_count,
            cool_down_seconds=cool_down_seconds,
            tunnel_ready_timeout_seconds=tunnel_ready_timeout_seconds,
            batch_size=batch_size,
            random_seed=random_seed,
        )

class MeasurementStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        ensure_dir(db_path.parent)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;") # https://sqlite.org/pragma.html
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.row_factory = sqlite3.Row
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
                tunnel_packet_loss_pct REAL,
                vpn_connect_time_ms REAL
            );

            CREATE TABLE IF NOT EXISTS dns_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                vantage_id TEXT NOT NULL,
                ovpn_file TEXT NOT NULL,
                protocol TEXT NOT NULL,
                mode TEXT NOT NULL,
                sample_index INTEGER NOT NULL,
                qname TEXT NOT NULL,
                query_type TEXT NOT NULL,
                target TEXT NOT NULL,
                latency_ms REAL,
                exit_code INTEGER NOT NULL,
                raw_output TEXT,
                error TEXT,
                UNIQUE(vantage_id, protocol, mode, sample_index)
            );

            CREATE INDEX IF NOT EXISTS idx_dns_samples_vantage
                ON dns_samples(vantage_id, protocol, mode);
            """
        )
        self.conn.commit()

    def start_vpn_session(self, vantage_id: str, ovpn_file: str) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO vpn_sessions(created_at, vantage_id, ovpn_file, status)
            VALUES(?, ?, ?, ?)
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
                json.dumps(tunnel_rtt) if tunnel_rtt is not None else None,
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
    # check if mmeasurement already exists -> can resume measurement
    def sample_exists(self, vantage_id: str, protocol: str, mode: str, sample_index: int) -> bool:
        row = self.conn.execute(
            """
            SELECT 1
            FROM dns_samples
            WHERE vantage_id = ? AND protocol = ? AND mode = ? AND sample_index = ?
            """,
            (vantage_id, protocol, mode, sample_index),
        ).fetchone()
        return row is not None

    def upsert_sample(self, *, vantage_id: str, ovpn_file: str, protocol: str, mode: str, sample_index: int, qname: str, query_type: str, target: str, latency_ms: Optional[float], exit_code: int, raw_output: str, error: Optional[str] = None) -> None:
        self.conn.execute(
            """
            INSERT INTO dns_samples(
                created_at, vantage_id, ovpn_file, protocol, mode, sample_index,
                qname, query_type, target, latency_ms, exit_code, raw_output, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(vantage_id, protocol, mode, sample_index) DO UPDATE SET
                created_at = excluded.created_at,
                ovpn_file = excluded.ovpn_file,
                qname = excluded.qname,
                query_type = excluded.query_type,
                target = excluded.target,
                latency_ms = excluded.latency_ms,
                exit_code = excluded.exit_code,
                raw_output = excluded.raw_output,
                error = excluded.error
            """,
            (
                utc_now(),
                vantage_id,
                ovpn_file,
                protocol,
                mode,
                sample_index,
                qname,
                query_type,
                target,
                latency_ms,
                exit_code,
                raw_output,
                error,
            ),
        )
        self.conn.commit()

    # not used, delete
    def export_csv(self, path: Path) -> None:
        rows = self.conn.execute(
            """
            SELECT created_at, vantage_id, ovpn_file, protocol, mode, sample_index,
                   qname, query_type, target, latency_ms, exit_code, error
            FROM dns_samples
            ORDER BY vantage_id, protocol, mode, sample_index
            """
        ).fetchall()
        ensure_dir(path.parent)
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "created_at",
                    "vantage_id",
                    "ovpn_file",
                    "protocol",
                    "mode",
                    "sample_index",
                    "qname",
                    "query_type",
                    "target",
                    "latency_ms",
                    "exit_code",
                    "error",
                ]
            )
            for row in rows:
                writer.writerow([row[k] for k in row.keys()])

# use sudo!
def default_openvpn_command() -> list[str]:
    if os.geteuid() == 0:
        return ["openvpn"]
    from shutil import which
    if which("sudo"):
        return ["sudo", "openvpn"]
    return ["openvpn"]


def build_kdig_command(*, kdig_binary: str, protocol: ProtocolSpec, query_type: str, qnames: list[str], reuse_connection: bool, query_timeout_seconds: float) -> list[str]:
    
    cmd = [kdig_binary, "+noall", "+stats", "-4", f"+timeout={int(query_timeout_seconds)}"]
    if reuse_connection:
        cmd.append("+keepopen")
    else:
        cmd.append("+nokeepopen")

    cmd.append(protocol.kdig_server_token())
    cmd.extend(protocol.extra_args)
    cmd.append(query_type)
    cmd.extend(qnames)
    return cmd


def run_command(argv: list[str], *, timeout: Optional[float] = None, capture_output: bool = True, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    LOG.debug("Executing: %s", " ".join(argv))
    # check should be False to avoid CalledProcessError
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture_output,
        timeout=timeout,
        check=False,
    )

def get_exit_ip() -> Optional[str]:
    try:
        proc = run_command(
            ["curl", "-4", "-s", "https://api.ipify.org"],
            timeout = 10,
        )
        if proc.returncode == 0:
            ip = proc.stdout.strip()
            if ip:
                return ip
    except Exception:
        pass
    return None


'''
UNUSED
def wait_for_openvpn_tunnel(*, ping_binary: str, gateway_ip: str, timeout_seconds: float, ping_timeout_seconds: float) -> dict[str, float]:
    deadline = time.monotonic() + timeout_seconds
    last_output = ""
    while time.monotonic() < deadline:
        proc = run_command(
            [
                ping_binary,
                "-c",
                "1",
                "-W",
                str(int(max(1, round(ping_timeout_seconds)))),
                gateway_ip,
            ],
            timeout=ping_timeout_seconds + 2.0,
        )
        last_output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            rtt = parse_ping_rtt(last_output)
            if rtt is not None:
                return rtt
            return {"min": 0.0, "avg": 0.0, "max": 0.0, "mdev": 0.0}
        time.sleep(1.0)
    raise MeasurementError(
        f"VPN tunnel did not become ready within {timeout_seconds:.0f}s. Last ping output:\n{last_output}"
    )
'''

def measure_tunnel_latency(*, ping_binary: str, gateway_ip: str, ping_count: int, ping_timeout_seconds: float) -> dict[str, float]:
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
        raise MeasurementError(f"Ping error :\n{output}")
    return rtt


def start_openvpn(openvpn_command: Iterable[str], ovpn_file: Path, auth_user_pass_file: Path) -> subprocess.Popen[str]:
    argv = list(openvpn_command) + ["--config", str(ovpn_file), "--auth-user-pass", str(auth_user_pass_file)]
    print("ARGV:", argv)
    LOG.info("Starting OpenVPN: %s", " ".join(argv))
    #proc = subprocess.run
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    return proc

def stop_process(proc: Optional[subprocess.Popen[str]]) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
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

def collect_openvpn_logs(proc: subprocess.Popen[str], *, max_lines: int = 2000) -> str:
    lines: list[str] = []
    if proc.stdout is None:
        return ""
    while len(lines) < max_lines:
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line)
    return "".join(lines)


def wait_for_openvpn_ready(proc: subprocess.Popen[str], timeout_seconds: float) -> str:
    if proc.stdout is None:
        raise MeasurementError("OpenVPN stdout error")
    deadline = time.monotonic() + timeout_seconds
    seen: list[str] = []
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if line:
            seen.append(line)
            LOG.debug("[openvpn] %s", line.rstrip())
            if "Initialization Sequence Completed" in line:
                return "".join(seen)
        else:
            time.sleep(0.2)
    full_log = "".join(seen)
    if proc.poll() is not None:
        full_log += collect_openvpn_logs(proc)
        raise MeasurementError(f"OpenVPN exited before becoming ready:\n{full_log}")
    raise MeasurementError(f"OpenVPN did not become ready within {timeout_seconds:.0f}s. Logs:\n{full_log}")


def run_kdig_batch(*, protocol: ProtocolSpec, query_type: str, qnames: list[str], kdig_binary: str, query_timeout_seconds: float, reuse_connection: bool) -> tuple[int, str, list[float]]:
    argv = build_kdig_command(
        kdig_binary=kdig_binary,
        protocol=protocol,
        query_type=query_type,
        qnames=qnames,
        reuse_connection=reuse_connection,
        query_timeout_seconds=query_timeout_seconds,
    )
    proc = run_command(argv, timeout=max(10.0, query_timeout_seconds * len(qnames) + 10.0))
    output = (proc.stdout or "") + (proc.stderr or "")
    latencies = parse_kdig_query_times(output)
    return proc.returncode, output, latencies


def run_measurement_batch(*, store: MeasurementStore, run_cfg: RunConfig, vantage_id: str, ovpn_file: Path, protocol: ProtocolSpec, protocol_name: str, mode: str, sample_offset: int, qnames: list[str]) -> None:
    if mode == "full_cold":
        for idx, qname in enumerate(qnames, start=sample_offset):
            LOG.info(
                "[%s][%s] sample %d/%d",
                protocol_name,
                mode,
                idx + 1,
                len(qnames),
            )
            if store.sample_exists(vantage_id, protocol_name, mode, idx):
                continue
            last_error: Optional[str] = None
            last_output = ""
            for attempt in range(run_cfg.retry_count + 1):
                rc, output, latencies = run_kdig_batch(
                    protocol=protocol,
                    query_type=run_cfg.query_type,
                    qnames=[qname],
                    kdig_binary=run_cfg.kdig_binary,
                    query_timeout_seconds=run_cfg.query_timeout_seconds,
                    reuse_connection=False,
                )
                last_output = output
                if rc == 0 and len(latencies) >= 1:
                    store.upsert_sample(
                        vantage_id=vantage_id,
                        ovpn_file=str(ovpn_file),
                        protocol=protocol_name,
                        mode=mode,
                        sample_index=idx,
                        qname=qname,
                        query_type=run_cfg.query_type,
                        target=protocol.server,
                        latency_ms=latencies[0],
                        exit_code=rc,
                        raw_output=output,
                        error=None,
                    )
                    break
                last_error = f"attempt={attempt + 1} rc={rc} parsed={len(latencies)}"
                time.sleep(0.5 * (attempt + 1))
            else:
                store.upsert_sample(
                    vantage_id=vantage_id,
                    ovpn_file=str(ovpn_file),
                    protocol=protocol_name,
                    mode=mode,
                    sample_index=idx,
                    qname=qname,
                    query_type=run_cfg.query_type,
                    target=protocol.server,
                    latency_ms=None,
                    exit_code=1,
                    raw_output=last_output,
                    error=last_error,
                )
        return

    # kdig requires multiple qnames in the same invocation if connection reuse is enabled
    batch_size = max(1, run_cfg.batch_size)
    for batch_start in range(0, len(qnames), batch_size):
        LOG.info(
            "[%s][%s] batch %d-%d / %d",
            protocol_name,
            mode,
            batch_start + 1,
            min(batch_start + batch_size, len(qnames)),
            len(qnames),
        )
        batch = qnames[batch_start:batch_start + batch_size]
        sample_indexes = list(range(sample_offset + batch_start, sample_offset + batch_start + len(batch)))

        # skip entire batch if every sample is already present
        if all(
            store.sample_exists(vantage_id, protocol_name, mode, idx)
            for idx in sample_indexes
        ):
            continue

        last_output = ""
        parsed: list[float] = []
        rc = 1
        for attempt in range(run_cfg.retry_count + 1):
            rc, output, latencies = run_kdig_batch(
                protocol=protocol,
                query_type=run_cfg.query_type,
                qnames=batch,
                kdig_binary=run_cfg.kdig_binary,
                query_timeout_seconds=run_cfg.query_timeout_seconds,
                reuse_connection=True,
            )
            last_output = output
            parsed = latencies
            if rc == 0 and len(parsed) >= len(batch):
                break
            time.sleep(0.5 * (attempt + 1))
        if rc != 0 or len(parsed) < len(batch):
            LOG.warning(
                "Batch failed for %s %s %s (expected %d replies, got %d).",
                vantage_id,
                protocol_name,
                mode,
                len(batch),
                len(parsed),
            )
        for idx, qname, latency in zip(sample_indexes, batch, parsed):
            if store.sample_exists(vantage_id, protocol_name, mode, idx):
                continue
            store.upsert_sample(
                vantage_id=vantage_id,
                ovpn_file=str(ovpn_file),
                protocol=protocol_name,
                mode=mode,
                sample_index=idx,
                qname=qname,
                query_type=run_cfg.query_type,
                target=protocol.server,
                latency_ms=latency,
                exit_code=rc,
                raw_output=last_output,
                error=None if rc == 0 else f"batch_rc={rc}",
            )

        # pad reslts with failures if kdig returned fewer latencies than size
        if len(parsed) < len(batch):
            for idx, qname in zip(sample_indexes[len(parsed):], batch[len(parsed):]):
                if store.sample_exists(vantage_id, protocol_name, mode, idx):
                    continue
                store.upsert_sample(
                    vantage_id=vantage_id,
                    ovpn_file=str(ovpn_file),
                    protocol=protocol_name,
                    mode=mode,
                    sample_index=idx,
                    qname=qname,
                    query_type=run_cfg.query_type,
                    target=protocol.server,
                    latency_ms=None,
                    exit_code=rc,
                    raw_output=last_output,
                    error=f"missing_parse_output expected_index={idx}",
                )


def run_one_vantage(*, store: MeasurementStore, run_cfg: RunConfig, ovpn_file: Path) -> None:
    vantage_id = ovpn_file.stem
    session_id = store.start_vpn_session(vantage_id, str(ovpn_file))
    openvpn_proc: Optional[subprocess.Popen[str]] = None
    tunnel_rtt: Optional[dict[str, float]] = None

    try:
        openvpn_proc = start_openvpn(run_cfg.openvpn_command, ovpn_file, run_cfg.auth_user_pass_file)
        LOG.info(
            "[%s] Waiting for VPN tunnel...",
            vantage_id,
        )
        vpn_start = time.monotonic()
        wait_for_openvpn_ready(openvpn_proc, run_cfg.tunnel_ready_timeout_seconds)
        LOG.info(
            "[%s] OpenVPN connected",
            vantage_id,
        )
        vpn_connect_time_ms = (time.monotonic() - vpn_start) * 1000.0
        tunnel_rtt = measure_tunnel_latency(
            ping_binary=run_cfg.ping_binary,
            gateway_ip=run_cfg.gateway_ip,
            ping_count=run_cfg.ping_count,
            ping_timeout_seconds=run_cfg.ping_timeout_seconds,
        )
        LOG.info(
            "[%s] Tunnel RTT avg=%.2f ms",
            vantage_id,
            tunnel_rtt["avg"],
        )
        exit_ip = get_exit_ip()
        LOG.info(
            "[%s] Exit IP: %s",
            vantage_id,
            exit_ip,
        )                
        if not exit_ip:
            raise MeasurementError(
                "VPN connected but could no exit IP"
            )

        store.finish_vpn_session(session_id, status="ready", tunnel_rtt=tunnel_rtt, exit_ip=exit_ip, vpn_connect_time_ms=vpn_connect_time_ms,)
        # not sure if reproducible
        rng = random.Random(run_cfg.random_seed + hash(vantage_id))
        for protocol_name in ("do53", "dot", "doh", "doq"):
            protocol = run_cfg.protocols[protocol_name]
            for mode in measurement_modes():
                same_name = mode == "full_warm"
                qnames = generate_qnames(run_cfg.base_domain,run_cfg.samples_per_mode,same_name=same_name,prefix=f"{protocol_name}-{mode}")
                if mode != "full_cold":
                    rng.shuffle(qnames)
                LOG.info(
                    "Vantage=%s protocol=%s mode=%s samples=%d (%s)",
                    vantage_id,
                    protocol_display_name(protocol_name),
                    mode,
                    len(qnames),
                    mode_description(mode),
                )
                run_measurement_batch(
                    store=store,
                    run_cfg=run_cfg,
                    vantage_id=vantage_id,
                    ovpn_file=ovpn_file,
                    protocol=protocol,
                    protocol_name=protocol_name,
                    mode=mode,
                    sample_offset=0,
                    qnames=qnames,
                )
                time.sleep(run_cfg.cool_down_seconds)
        store.finish_vpn_session(session_id, status="completed", tunnel_rtt=tunnel_rtt, exit_ip=exit_ip, vpn_connect_time_ms=vpn_connect_time_ms)
    except Exception as exc:
        store.finish_vpn_session(session_id, status="failed", tunnel_rtt=tunnel_rtt, notes=str(exc))
        raise
    finally:
        stop_process(openvpn_proc)


def country_code_from_ovpn_file(path: Path) -> Optional[str]:
    m = re.match(
        r"^([a-z]{2})(\d+)",
        path.stem,
        re.IGNORECASE,
    )
    if not m:
        return None
    return m.group(1).lower()


def group_ovpn_files_by_country(ovpn_dir: Path) -> dict[str, list[Path]]:
    if not ovpn_dir.is_dir():
        raise MeasurementError(
            f"OpenVPN config directory not found: {ovpn_dir}"
        )

    files = sorted(
        p
        for p in ovpn_dir.iterdir()
        if p.suffix == ".ovpn" and p.is_file()
    )

    if not files:
        raise MeasurementError(f"No ovpn files found in {ovpn_dir}")

    groups: dict[str, list[Path]] = {}

    for f in files:
        country = country_code_from_ovpn_file(f)
        if country is None:
            continue
        groups.setdefault(country,[]).append(f)

    rng = random.Random(42)
    # should be deterministic now
    for members in groups.values():
        rng.shuffle(members)

    LOG.info(
        "Loaded %d VPN configs across %d countries",
        sum(len(v) for v in groups.values()),
        len(groups),
    )
    return groups


def validate_inputs(run_cfg: RunConfig) -> None:
    if not run_cfg.auth_user_pass_file.is_file():
        raise MeasurementError(f"Auth credential file not found: {run_cfg.auth_user_pass_file}")
    if not run_cfg.ovpn_dir.is_dir():
        raise MeasurementError(f"OVPN directory not found: {run_cfg.ovpn_dir}")
    ensure_dir(run_cfg.output_dir)
    which_or_die(run_cfg.ping_binary)
    which_or_die(run_cfg.kdig_binary)
    for binary in run_cfg.openvpn_command:
        if binary == "sudo":
            continue
        if "/" not in binary:
            which_or_die(binary)


def setup_signal_handlers() -> None:
    def _handler(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"Interrupted by signal {signum}")
    #https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format=(
            "%(asctime)s | "
            "%(levelname)-8s | "
            "%(message)s"
        ),
        datefmt="%H:%M:%S",
    )

def main() -> int:
    parser = argparse.ArgumentParser(description="Run raw DoX measurements across VPN vantage points.")
    parser.add_argument("--config", required=True, help="Path to JSON config file.")
    parser.add_argument(
        "--ovpn",
        help="Optional path single ovpn file. All in ovpn_dir are used if omitted",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="More logs",
    )
    args = parser.parse_args()
    setup_logging(args.verbose)
    setup_signal_handlers()
    cfg_raw = load_config(Path(args.config).expanduser())
    run_cfg = RunConfig.from_dict(cfg_raw)
    validate_inputs(run_cfg)

    store = MeasurementStore(run_cfg.output_dir / "measurements.sqlite3")
    try:
        if args.ovpn:
            ovpn_files = [Path(args.ovpn).expanduser()]
            for ovpn_file in ovpn_files:
                try:
                    run_one_vantage(
                        store=store,
                        run_cfg=run_cfg,
                        ovpn_file=ovpn_file,
                    )
                except Exception:
                    LOG.exception(
                        "Vantage point failed: %s",
                        ovpn_file.name,
                    )
        else:
            country_groups = group_ovpn_files_by_country(
                run_cfg.ovpn_dir
            )
            for country in sorted(country_groups):
                candidates = country_groups[country]
                successes = 0
                LOG.info(
                    "Selecting 3 exit points for %s",
                    country.upper(),
                )
                for ovpn_file in candidates:
                    if successes >= 3:
                        break
                    try:
                        LOG.info(
                            "Trying %s (%d/3)",
                            ovpn_file.name,
                            successes,
                        )
                        run_one_vantage(
                            store=store,
                            run_cfg=run_cfg,
                            ovpn_file=ovpn_file,
                        )
                        successes += 1
                        LOG.info(
                            "Accepted %s (%d/3)",
                            ovpn_file.name,
                            successes,
                        )
                    except Exception:
                        LOG.exception(
                            "Skipping failed VPN %s",
                            ovpn_file.name,
                        )
                        continue
                if successes < 3:
                    LOG.warning(
                        "Country %s only produced %d successful exits",
                        country.upper(),
                        successes,
                    )
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
