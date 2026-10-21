#!/usr/bin/env python3
"""Performance suite. Writes build/perf_results.json (one record per measurement) and prints a summary.

  python benchmarks/perf/run_perf.py [--only A,B,C,D,E,F] [--quick]

A in-process engine, rules only         B sanitize vs detect cost           C HTTP server, rules only
D NLP detectors (presidio / gliner / all, sizes + concurrency)              E soak + hot reload under load
F reload latency

Requires: target/release/{dlp,dlp-server}, the NLP service on :8791 for D/E (pids found via /proc).
CPU% = (utime+stime delta)/wall of the measured processes (100% = one core); RSS from /proc/<pid>/status.
"""
import argparse, json, os, platform, subprocess, sys, time, urllib.request, glob

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DLP = os.path.join(ROOT, "target/release/dlp")
SERVER_BIN = os.path.join(ROOT, "target/release/dlp-server")
OUT = os.path.join(ROOT, "build/perf_results.json")
KEY = open(os.path.join(ROOT, "build/run/admin.key")).read().strip()
CLK = os.sysconf("SC_CLK_TCK")
PORT = 18081
URL = f"http://127.0.0.1:{PORT}"
NLP_URL = "http://127.0.0.1:8791"
results = []


def pids_by_cmd(substr):
    out = []
    for p in glob.glob("/proc/[0-9]*"):
        try:
            cmd = open(p + "/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="ignore")
            if substr in cmd and "run_perf" not in cmd and "pgrep" not in cmd:
                out.append(int(os.path.basename(p)))
        except Exception:
            pass
    return out


def cpu_ticks(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return int(f[11]) + int(f[12])
    except Exception:
        return 0


def rss_mb(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS:"):
                return int(l.split()[1]) / 1024
    except Exception:
        pass
    return 0.0


def hwm_mb(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmHWM:"):
                return int(l.split()[1]) / 1024
    except Exception:
        pass
    return 0.0


class Watch:
    def __init__(self, named):
        self.named = named  # {label: pid}
    def __enter__(self):
        self.t0 = time.time(); self.c0 = {k: cpu_ticks(p) for k, p in self.named.items()}
        return self
    def __exit__(self, *a):
        el = time.time() - self.t0
        self.cpu = {k: round((cpu_ticks(p) - self.c0[k]) / CLK / el * 100, 1) for k, p in self.named.items()}
        self.rss = {k: round(rss_mb(p), 1) for k, p in self.named.items()}


def record(group, name, data):
    data = dict(group=group, name=name, **data)
    results.append(data)
    json.dump({"env": ENV, "results": results}, open(OUT, "w"), indent=1)
    keys = ("qps", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "errors", "degraded_responses", "shed_503", "cpu_pct", "rss_mb")
    print(f"[{group}] {name:44s} " + " ".join(f"{k}={data[k]:.4g}" if isinstance(data.get(k), (int, float)) else f"{k}={data.get(k)}" for k in keys if k in data), flush=True)


def run_bench(args, watch=None):
    p = subprocess.run([DLP, "--db", os.path.join(ROOT, "build/run/perf.db"), "--rules-dir", os.path.join(ROOT, "rules"), "bench", "--json", *args], capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        return {"error": p.stderr[-300:]}
    return json.loads(p.stdout.strip().splitlines()[-1])


def http_bench(bytes_, threads, seconds, detectors, mode="detect", policy="audit-only", batch=1, watch=None):
    named = {"server": server_pid}
    if nlp_pid:
        named["nlp"] = nlp_pid
    with Watch(named) as w:
        r = run_bench(["--url", URL, "--key", KEY, "--bytes", str(bytes_), "--threads", str(threads), "--seconds", str(seconds), "--detectors", detectors, "--mode", mode, "--policy", policy, "--batch", str(batch)])
    r["cpu_pct"] = w.cpu.get("server", 0)
    r["cpu_pct_nlp"] = w.cpu.get("nlp", 0)
    r["rss_mb"] = w.rss.get("server", 0)
    r["rss_mb_nlp"] = w.rss.get("nlp", 0)
    return r


def env_info():
    cpu = [l.split(":")[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")]
    mem = int([l for l in open("/proc/meminfo") if l.startswith("MemTotal")][0].split()[1]) / 1048576
    def sh(c):
        try:
            return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
        except Exception:
            return ""
    return {"cpu_model": cpu[0] if cpu else "?", "logical_cpus": len(cpu), "mem_gb": round(mem, 1), "os": platform.platform(), "rustc": sh("rustc --version"), "python": platform.python_version(),
            "torch": sh(f"{ROOT}/../venv/bin/python -s -c 'import torch;print(torch.__version__, torch.get_num_threads())' 2>/dev/null"), "hyperscan": sh("dpkg -s libhyperscan5 2>/dev/null | grep ^Version"), "date": time.strftime("%Y-%m-%d %H:%M:%S")}


ap = argparse.ArgumentParser()
ap.add_argument("--only", default="A,B,C,D,E,F")
ap.add_argument("--quick", action="store_true")
a = ap.parse_args()
only = set(a.only.split(","))
S = 2 if a.quick else 5
ENV = env_info()
print(json.dumps(ENV, indent=1))

# ---- start an isolated perf server (large limits so the 1 MiB / NLP cases are measurable)
os.makedirs(os.path.join(ROOT, "build/run"), exist_ok=True)
for f in glob.glob(os.path.join(ROOT, "build/run/perf.db*")):
    os.remove(f)
subprocess.run([DLP, "--db", os.path.join(ROOT, "build/run/perf.db"), "--rules-dir", os.path.join(ROOT, "rules"), "init"], capture_output=True)
nlp_up = False
try:
    nlp_up = json.loads(urllib.request.urlopen(NLP_URL + "/health", timeout=2).read())["status"] == "ok"
except Exception:
    pass
cmd = [SERVER_BIN, "--listen", f"127.0.0.1:{PORT}", "--db", os.path.join(ROOT, "build/run/perf.db"), "--rules-dir", os.path.join(ROOT, "rules"), "--api-keys", os.path.join(ROOT, "build/run/keys.json"),
       "--max-inflight", "512", "--request-timeout-secs", "1800", "--nlp-max-bytes", "3000000", "--max-text-bytes", "4194304"]
if nlp_up:
    cmd += ["--nlp-url", NLP_URL]
srv = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=open(os.path.join(ROOT, "build/run/perf_server.log"), "w"))
server_pid = srv.pid
nlp_pids = pids_by_cmd("dlp_nlp.app")
nlp_pid = nlp_pids[0] if nlp_pids else None
for _ in range(60):
    try:
        urllib.request.urlopen(URL + "/health", timeout=1); break
    except Exception:
        time.sleep(0.2)
print("server pid", server_pid, "nlp pid", nlp_pid, "nlp_up", nlp_up, flush=True)
SIZES = [100, 1000, 10000, 100000, 1000000]
RULES = "regex,secret,dictionary"
try:
    if "A" in only:   # in-process engine, rules only
        for sz in SIZES:
            r = run_bench(["--bytes", str(sz), "--threads", "1", "--seconds", str(S), "--detectors", RULES, "--policy", "rules-only"])
            record("A", f"in-process rules, {sz} B, 1 thread", r)
        for th in (1, 10, 50, 100):
            r = run_bench(["--bytes", "1000", "--threads", str(th), "--seconds", str(S), "--detectors", RULES, "--policy", "rules-only"])
            record("A", f"in-process rules, 1 KB, {th} threads", r)
    if "B" in only:   # sanitize cost
        for sz in (1000, 100000):
            for mode in ("detect", "sanitize"):
                r = run_bench(["--bytes", str(sz), "--threads", "4", "--seconds", str(S), "--detectors", RULES, "--policy", "rules-only", "--mode", mode])
                record("B", f"in-process rules {mode}, {sz} B, 4 threads", r)
    if "C" in only:
        for sz in SIZES:
            record("C", f"HTTP rules, {sz} B, 1 client", http_bench(sz, 1, S, RULES))
        for th in (1, 10, 50, 100):
            record("C", f"HTTP rules, 1 KB, {th} clients", http_bench(1000, th, S, RULES))
        for b in (16, 64):
            record("C", f"HTTP rules batch x{b}, 1 KB, 10 clients", http_bench(1000, 10, S, RULES, batch=b))
        record("C", "HTTP rules sanitize, 1 KB, 10 clients", http_bench(1000, 10, S, RULES, mode="sanitize"))
    if "D" in only and nlp_up:
        for det, label in (("presidio", "presidio"), ("gliner", "gliner"), ("regex,secret,dictionary,presidio,gliner", "ALL detectors")):
            for sz in (100, 1000, 10000):
                record("D", f"HTTP {label}, {sz} B, 1 client", http_bench(sz, 1, 6 if not a.quick else 3, det))
            if det != "gliner":
                record("D", f"HTTP {label}, 100000 B, 1 client", http_bench(100000, 1, 8, det))
        # large inputs through the models: honest single-shot numbers
        for sz, det, label in ((100000, "gliner", "gliner"), (100000, "regex,secret,dictionary,presidio,gliner", "ALL detectors"), (1000000, "presidio", "presidio"), (1000000, "regex,secret,dictionary,presidio,gliner", "ALL detectors")):
            r = http_bench(sz, 1, 1, det)   # one request is enough: the loop stops after the first completion past the deadline
            record("D", f"HTTP {label}, {sz} B, 1 request", r)
        for th in (1, 10, 50, 100):
            record("D", f"HTTP ALL detectors, 1 KB, {th} clients", http_bench(1000, th, 20 if not a.quick else 8, "regex,secret,dictionary,presidio,gliner"))
        record("D", "HTTP ALL detectors batch x16, 1 KB, 4 clients", http_bench(1000, 4, 20, "regex,secret,dictionary,presidio,gliner", batch=16))
    if "F" in only:
        for i in range(3):
            t = time.time()
            req = urllib.request.Request(URL + "/v1/rules/reload", method="POST", headers={"Authorization": f"Bearer {KEY}"})
            body = json.loads(urllib.request.urlopen(req).read())
            record("F", f"reload unchanged #{i}", {"wall_ms": (time.time() - t) * 1000, "compile_ms": body["compile_ms"], "changed": body["changed"], "rules_enabled": body["rules_enabled"]})
    if "E" in only:
        # hot reload under load: 10 clients hammer the server while the rule set is changed + reloaded every 3 s
        import threading, sqlite3
        stop = {"v": False}
        reload_ms = []
        def reloader():
            con = sqlite3.connect(os.path.join(ROOT, "build/run/perf.db"), timeout=30)
            i = 0
            while not stop["v"]:
                i += 1
                con.execute("UPDATE rules SET confidence = ? WHERE id='email'", (0.90 + (i % 5) * 0.01,)); con.commit()
                t = time.time()
                req = urllib.request.Request(URL + "/v1/rules/reload", method="POST", headers={"Authorization": f"Bearer {KEY}"})
                try:
                    b = json.loads(urllib.request.urlopen(req, timeout=60).read()); reload_ms.append(((time.time() - t) * 1000, b["compile_ms"], b["changed"]))
                except Exception as e:
                    reload_ms.append((-1, -1, str(e)))
                time.sleep(3)
        th = threading.Thread(target=reloader); th.start()
        r = http_bench(1000, 10, 30 if not a.quick else 8, RULES)
        stop["v"] = True; th.join()
        r["reloads"] = len(reload_ms); r["reload_wall_ms_avg"] = sum(x[0] for x in reload_ms) / max(1, len(reload_ms)); r["reload_failures"] = sum(1 for x in reload_ms if x[0] < 0); r["reload_changed"] = sum(1 for x in reload_ms if x[2] is True)
        record("E", "HTTP rules 1 KB, 10 clients, hot reload every 3 s", r)
        # soak
        secs = 60 if a.quick else 600
        samples = []
        t_end = time.time() + secs
        def sampler():
            while time.time() < t_end:
                samples.append((round(time.time() - (t_end - secs)), round(rss_mb(server_pid), 1)))
                time.sleep(10)
        st = threading.Thread(target=sampler); st.start()
        r = http_bench(1000, 10, secs, RULES)
        st.join()
        r["rss_samples_mb"] = samples; r["rss_start_mb"] = samples[0][1]; r["rss_end_mb"] = samples[-1][1]; r["rss_peak_mb"] = round(hwm_mb(server_pid), 1)
        record("E", f"soak {secs}s rules 1 KB, 10 clients", r)
        if nlp_up:
            secs2 = 60 if a.quick else 240
            r = http_bench(1000, 4, secs2, "regex,secret,dictionary,presidio,gliner")
            r["rss_peak_mb_nlp"] = round(hwm_mb(nlp_pid), 1) if nlp_pid else None
            record("E", f"soak {secs2}s ALL detectors 1 KB, 4 clients", r)
finally:
    srv.terminate()
    try:
        srv.wait(10)
    except Exception:
        srv.kill()
print("wrote", OUT)
