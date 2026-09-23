#!/usr/bin/env python3
"""Load the live mihomo route with bounded HTTP transfers and collect perf.

Requires Python/PyYAML, curl, perf, and passwordless sudo. Does not change
mihomo configuration, proxy selection, routing, or service state. Route evidence
comes from /connections, filtered to curl's actual source ports. A test aborts
if a matched connection uses an unexpected proxy. Default transport is the
machine's existing transparent route; no explicit HTTP proxy is introduced.

Example:
  python scripts/perf-bandwidth.py --label direct --expect-proxy 本地直连 \
    --url https://mirrors.tuna.tsinghua.edu.cn/archlinux/iso/latest/archlinux-x86_64.iso
  python scripts/perf-bandwidth.py --label hy2 --expect-proxy '🇯🇵 h4' \
    --url 'https://speedtest.tokyo2.linode.com/1GB-tokyo2.bin'

Outputs are private. Raw perf stacks can contain information about other live
connections; do not publish the output directory without inspecting it.
"""
import argparse
import collections
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import threading
import time
import urllib.parse
import urllib.request

import yaml


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def read(path):
    return Path(path).read_text().strip()


def proc_ticks(path):
    fields = read(path).rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


def child_tcp_ports(pids):
    """Find TCP source ports owned by the supplied live curl processes."""
    inodes = set()
    for pid in pids:
        for fd in Path(f"/proc/{pid}/fd").glob("*"):
            try:
                target = os.readlink(fd)
            except (FileNotFoundError, ProcessLookupError):
                continue  # curl may close a socket or exit during the snapshot
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
    ports = set()
    if not inodes:
        return ports
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in read(table).splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[9] in inodes:
                ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    return ports


def snapshot(pid, interface):
    net = Path("/sys/class/net") / interface / "statistics"
    threads = {}
    for p in Path(f"/proc/{pid}/task").glob("*/stat"):
        try:
            threads[p.parent.name] = proc_ticks(p)
        except FileNotFoundError:
            pass
    return {
        "time": time.monotonic(), "cpu_ticks": proc_ticks(f"/proc/{pid}/stat"),
        "threads": threads,
        "net": {k: int(read(net / k)) for k in
                ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped", "rx_errors", "tx_errors")},
        "system_ticks": [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:]],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--label", required=True)
    p.add_argument("--url", action="append", default=[])
    p.add_argument("--expect-proxy")
    p.add_argument("--connections", type=int, default=4)
    p.add_argument("--seconds", type=int, default=30)
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument("--interface", default="enp4s0")
    p.add_argument("--config", default="/etc/mihomo/config.yaml")
    p.add_argument("--pid", type=int)
    p.add_argument("--output", default="/tmp/mihomo-bandwidth-perf")
    p.add_argument("--no-perf", action="store_true", help="short bandwidth ramp only")
    p.add_argument("--idle", action="store_true")
    p.add_argument("--symfs", help="offline symbolized executable tree for perf report")
    p.add_argument("--upload", help="POST this file to each URL instead of downloading")
    p.add_argument("--http-proxy", help="optional explicit proxy for an isolated A/B instance")
    p.add_argument("--count-io", action="store_true", help="count write and recvmmsg syscalls in perf stat")
    a = p.parse_args()
    if not a.idle and (not a.url or not a.expect_proxy):
        p.error("load tests require --url and --expect-proxy")
    if min(a.seconds, a.connections) < 1 or a.warmup < 0:
        p.error("invalid duration or concurrency")
    if any(urllib.parse.urlsplit(u).scheme not in ("https", "http") for u in a.url):
        p.error("only HTTP(S) URLs are supported")
    os.umask(0o077)
    out = Path(a.output).resolve() / a.label
    out.mkdir(parents=True, exist_ok=False)
    pid = a.pid or int(subprocess.check_output(["systemctl", "show", "mihomo", "-p", "MainPID", "--value"]))
    config = yaml.safe_load(read(a.config))
    controller = config["external-controller"].replace("0.0.0.0", "127.0.0.1")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path):
        req = urllib.request.Request("http://" + controller + path,
                                     headers={"Authorization": "Bearer " + config.get("secret", "")})
        with opener.open(req, timeout=3) as r:
            return json.load(r)

    version = api("/version")
    meta = {"pid": pid, "version": version, "interface": a.interface,
            "urls": a.url, "expected_proxy": a.expect_proxy, "connections": a.connections,
            "seconds": a.seconds, "warmup": a.warmup, "upload": bool(a.upload),
            "http_proxy": a.http_proxy,
            "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "executable_sha256": subprocess.check_output(["sudo", "-n", "sha256sum", f"/proc/{pid}/exe"], text=True).split()[0]}
    (out / "metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2))
    (out / "snmp-before.txt").write_text(read("/proc/net/snmp"))
    stop = threading.Event()
    active = set()
    lock = threading.Lock()
    transfers = []
    worker_failures = []
    routes = {}
    matched = {}
    profilers = []
    handles = []
    original_kptr = None
    ticks = os.sysconf("SC_CLK_TCK")
    # Each worker has a bounded port range. Filter it further by socket ownership:
    # unrelated applications can use other ephemeral ports within that range.
    portbase = 40000 + (os.getpid() % 100) * 100
    load_start = time.monotonic()
    deadline = load_start + a.warmup + a.seconds

    def worker(i):
        while not stop.is_set() and time.monotonic() < deadline:
            url = a.url[i % len(a.url)]
            cmd = ["curl", "--noproxy", "*", "--silent", "--show-error", "--location",
                   "--fail", "--connect-timeout", "5", "--max-time", str(max(0.1, deadline-time.monotonic())),
                   "--local-port", f"{portbase+i*50}-{portbase+i*50+49}",
                   "--output", "/dev/null", "--write-out", "%{json}"]
            if a.http_proxy:
                cmd += ["--noproxy", "", "--proxy", a.http_proxy]
            if a.upload:
                cmd += ["--upload-file", a.upload, "--request", "POST", "--header", "Expect:",
                        "--header", "Content-Type: application/octet-stream"]
            start = time.monotonic()
            proc = subprocess.Popen(cmd + [url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with lock:
                active.add(proc)
                if stop.is_set():
                    proc.terminate()
            stdout, stderr = proc.communicate()
            with lock:
                active.discard(proc)
            try:
                data = json.loads(stdout)
            except (ValueError, TypeError):
                data = {}
            # Store only measurement fields, never curl's full JSON environment.
            item = {k: data.get(k) for k in ("http_code", "size_download", "size_upload", "speed_download", "time_total", "local_port", "remote_ip")}
            item.update(worker=i, start=start, end=time.monotonic(), returncode=proc.returncode, error=stderr[-300:])
            with lock:
                transfers.append(item)
            if data.get("http_code") in (403, 429):
                with lock:
                    worker_failures.append(f"HTTP {data['http_code']} from {urllib.parse.urlsplit(url).hostname}; stopped")
                stop.set()
                break
            if proc.returncode not in (0, 28) and not stop.is_set():
                stop.wait(1)

    def observe():
        if worker_failures:
            raise RuntimeError("; ".join(worker_failures))
        data = api("/connections")
        with lock:
            curl_pids = [proc.pid for proc in active if proc.poll() is None]
        source_ports = child_tcp_ports(curl_pids)
        for c in data.get("connections") or []:
            m = c["metadata"]
            port = int(m.get("sourcePort", 0))
            if port not in source_ports or not portbase <= port < portbase+a.connections*50:
                continue
            if a.expect_proxy not in c.get("chains", []):
                raise RuntimeError(f"unexpected route for {m.get('host')}:{port}: {c.get('chains')}")
            routes[c["id"]] = {"host": m.get("host"), "sourcePort": port,
                                "type": m.get("type"), "chains": c.get("chains"),
                                "remoteDestination": m.get("remoteDestination"), "rule": c.get("rule")}
            matched[c["id"]] = {"download": c["download"], "upload": c["upload"]}
        return sum(x["download"] for x in matched.values()), sum(x["upload"] for x in matched.values())

    def start_profiler(cmd, filename):
        f = open(out / filename, "w")
        handles.append(f)
        proc = subprocess.Popen(["sudo", "-n"] + cmd, stdout=f, stderr=f)
        profilers.append(proc)

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=a.connections)
    rows = []
    failure = None
    try:
        if not a.no_perf:
            original_kptr = read("/proc/sys/kernel/kptr_restrict")
            run(["sudo", "-n", "sysctl", "-q", "-w", "kernel.kptr_restrict=0"])
            with open(out / "kallsyms", "w") as f:
                run(["sudo", "-n", "cat", "/proc/kallsyms"], stdout=f)
        futures = [] if a.idle else [pool.submit(worker, i) for i in range(a.connections)]
        for _ in range(a.warmup):
            time.sleep(1)
            if not a.idle:
                observe()
        if not a.idle and not routes:
            raise RuntimeError("no matching live connections; cannot verify test route")
        if not a.no_perf:
            events = "task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults"
            if a.count_io:
                events += ",syscalls:sys_enter_write,syscalls:sys_enter_recvmmsg"
            start_profiler(["perf", "stat", "-p", str(pid), "-x", ",", "-o", str(out/"perf-stat.csv"),
                            "-e", events,
                            "--", "sleep", str(a.seconds)], "perf-stat.log")
            start_profiler(["perf", "record", "-p", str(pid), "-e", "cpu-clock", "-F", "499",
                            "--call-graph", "fp", "-o", str(out/"perf.data"),
                            "--", "sleep", str(a.seconds)], "perf-record.log")
        prev = snapshot(pid, a.interface)
        previous_bytes = observe() if not a.idle else (0, 0)
        measured_start = prev["time"]
        for i in range(a.seconds):
            time.sleep(max(0, measured_start + i + 1 - time.monotonic()))
            current_bytes = observe() if not a.idle else (0, 0)
            now = snapshot(pid, a.interface)
            dt = now["time"] - prev["time"]
            row = {"second": i+1, "interval": dt,
                   "cpu_cores": (now["cpu_ticks"]-prev["cpu_ticks"])/ticks/dt,
                   "hottest_thread_cores": max([max(0, n-prev["threads"].get(t,n))/ticks/dt for t,n in now["threads"].items()] or [0]),
                   "route_observed_rx_mbps": (current_bytes[0]-previous_bytes[0])*8/dt/1e6,
                   "route_observed_tx_mbps": (current_bytes[1]-previous_bytes[1])*8/dt/1e6}
            for key, n in now["net"].items():
                row[key+"_delta"] = n-prev["net"][key]
            row["nic_rx_mbps"] = row["rx_bytes_delta"]*8/dt/1e6
            row["nic_tx_mbps"] = row["tx_bytes_delta"]*8/dt/1e6
            sys_delta = [x-y for x,y in zip(now["system_ticks"],prev["system_ticks"])]
            row["system_busy_cores"] = (sum(sys_delta[:8])-sys_delta[3]-sys_delta[4])/ticks/dt
            row["system_softirq_cores"] = sys_delta[6]/ticks/dt
            rows.append(row)
            if i % 5 == 0 or i == a.seconds-1:
                print(f"{a.label} {i+1:2d}s RX {row['nic_rx_mbps']:.1f} TX {row['nic_tx_mbps']:.1f} Mbps mihomo {row['cpu_cores']:.2f} cores", flush=True)
            prev, previous_bytes = now, current_bytes
        for proc in profilers:
            if proc.wait(timeout=10) != 0:
                raise RuntimeError("perf failed; inspect profiler logs")
    except BaseException as exc:
        failure = repr(exc)
        raise
    finally:
        stop.set()
        # curl's bounded --max-time preserves final partial-transfer counters.
        # Give it a short opportunity to exit before forcing cancellation.
        if failure is None:
            concurrent.futures.wait(futures, timeout=1)
        with lock:
            for proc in active:
                if proc.poll() is None:
                    proc.terminate()
        pool.shutdown(wait=True)
        for proc in profilers:
            if proc.poll() is None:
                subprocess.run(["sudo", "-n", "kill", "-INT", str(proc.pid)], check=False)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    subprocess.run(["sudo", "-n", "kill", "-TERM", str(proc.pid)], check=False)
        for f in handles:
            f.close()
        if original_kptr is not None:
            run(["sudo", "-n", "sysctl", "-q", "-w", "kernel.kptr_restrict="+original_kptr])
        for filename, data in [("samples.json", rows), ("routes.json", list(routes.values())), ("transfers.json", transfers)]:
            (out/filename).write_text(json.dumps(data, ensure_ascii=False, indent=2))
        (out/"snmp-after.txt").write_text(read("/proc/net/snmp"))
        if rows:
            summary = {"label": a.label, "failure": failure, "route_connections": len(routes),
                       "transfers": len(transfers), "http_statuses": dict(collections.Counter(str(t["http_code"]) for t in transfers)),
                       "curl_payload_mbps_including_warmup": sum((t["size_upload"] if a.upload else t["size_download"]) or 0 for t in transfers)*8/(a.seconds+a.warmup)/1e6,
                       "note": "NIC includes background traffic. Route bytes are a sampled lower bound when requests finish between polls. CPU cores: 1.0 equals one logical CPU.",
                       "average": {k: statistics.mean(r[k] for r in rows) for k in
                                   ("nic_rx_mbps", "nic_tx_mbps", "cpu_cores", "system_busy_cores", "system_softirq_cores", "route_observed_rx_mbps", "route_observed_tx_mbps")},
                       "peak": {k: max(r[k] for r in rows) for k in ("nic_rx_mbps", "nic_tx_mbps", "hottest_thread_cores")}}
            (out/"summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
            print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    if not a.no_perf:
        run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(out/"perf.data"), str(out/"perf-stat.csv")])
        for extra, filename in [(["--no-children", "--call-graph", "none"], "perf-flat.txt"),
                                (["--children", "--call-graph", "graph,0.5,caller"], "perf-callgraph.txt")]:
            cmd = ["perf", "report", "-i", str(out/"perf.data"), "--stdio",
                   "--kallsyms", str(out/"kallsyms"), "--percent-limit", "0.5"] + extra
            if a.symfs:
                cmd += ["--symfs", a.symfs]
            with open(out/filename, "w") as f:
                run(cmd, stdout=f, stderr=subprocess.STDOUT)
    print("Saved:", out, flush=True)


if __name__ == "__main__":
    main()
