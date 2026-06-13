#!/usr/bin/env python3
import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.append("/usr/lib/python3/dist-packages")

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel


VENV_PY = os.path.expanduser("~/sdn-ids-venv-sys/bin/python3")
ATTACK_FLAG_FILE = "/tmp/sdn_attack_flag"


def sh(cmd, quiet=True):
    if quiet:
        return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, shell=True)


def set_attack_flag(value: int):
    with open(ATTACK_FLAG_FILE, "w") as f:
        f.write(str(int(value)))
        f.flush()


def wait_port(host, port, timeout=20):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def clean_environment():
    print("[CLEAN] Resetting ports, Mininet and OVS")
    sh("sudo pkill -f ml_service.py || true")
    sh("sudo pkill -f ryu.cmd.manager || true")
    sh("sudo pkill -f ryu-manager || true")
    sh("sudo fuser -k 5000/tcp || true")
    sh("sudo fuser -k 8080/tcp || true")
    sh("sudo fuser -k 6633/tcp || true")
    sh("sudo mn -c || true")
    sh("sudo service openvswitch-switch restart || true")
    sh("echo 0 | sudo tee /tmp/sdn_attack_flag >/dev/null")
    sh("sudo chmod 666 /tmp/sdn_attack_flag")


def start_ml(method, results_file, logs_dir):
    env = os.environ.copy()
    env["MODE"] = method
    env["RESULTS_FILE"] = str(results_file)
    env["ATTACK_FLAG_FILE"] = ATTACK_FLAG_FILE
    env["ML_PORT"] = "5000"

    log = open(Path(logs_dir) / f"ml_{method}.log", "w")

    print(f"[START] ML service: {method}")
    p = subprocess.Popen(
        [VENV_PY, "-u", "ml/ml_service.py"],
        env=env,
        stdout=log,
        stderr=log,
    )

    if not wait_port("127.0.0.1", 5000, timeout=20):
        raise RuntimeError("ML service did not become ready on port 5000")

    return p, log


def start_ryu(logs_dir):
    env = os.environ.copy()
    env["EVENTLET_NO_GREENDNS"] = "yes"
    env["ML_URL"] = "http://127.0.0.1:5000/score"
    env["POLL_INTERVAL"] = "0.5"

    log = open(Path(logs_dir) / "ryu.log", "w")

    print("[START] Ryu controller + exporter")
    p = subprocess.Popen(
        [
            VENV_PY,
            "-m",
            "ryu.cmd.manager",
            "--ofp-tcp-listen-port",
            "6633",
            "ryu.app.ofctl_rest",
            "controller/ryu_app.py",
            "controller/flow_exporter.py",
        ],
        env=env,
        stdout=log,
        stderr=log,
    )

    time.sleep(5)
    if not wait_port("127.0.0.1", 6633, timeout=20):
        print("[WARN] Ryu port 6633 check failed; continuing because Ryu import is fixed")

    return p, log


def start_mininet():
    print("[START] Mininet topology: single switch, 3 hosts")
    setLogLevel("error")

    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633,
    )

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.start()
    time.sleep(3)

    # Start iperf servers inside Mininet namespaces
    h2.cmd("iperf -s -u -p 5001 > /tmp/iperf_udp_server.log 2>&1 &")
    h2.cmd("iperf -s -p 5002 > /tmp/iperf_tcp_server.log 2>&1 &")

    return net


def benign_traffic(net, duration):
    h1, h2, h3 = net.get("h1", "h2", "h3")

    h1.cmd(f"timeout {duration}s ping -i 0.2 10.0.0.2 > /tmp/h1_ping.log 2>&1 &")
    h3.cmd(f"timeout {duration}s ping -i 0.3 10.0.0.1 > /tmp/h3_ping.log 2>&1 &")

    # Low-rate TCP background traffic
    h1.cmd(
        f"timeout {duration}s bash -c "
        f"'while true; do iperf -c 10.0.0.2 -p 5002 -t 3 >/tmp/tcp_bg.log 2>&1; sleep 2; done' &"
    )


def attack_traffic(net, duration, udp_bps, pulse_on, pulse_off):
    h1 = net.get("h1")

    cmd = (
        f"timeout {duration}s bash -c "
        f"'while true; do "
        f"iperf -u -c 10.0.0.2 -p 5001 -b {udp_bps} -t {pulse_on} "
        f">/tmp/udp_attack.log 2>&1; "
        f"sleep {pulse_off}; "
        f"done' &"
    )
    h1.cmd(cmd)


def run_phase(net, name, duration, udp_bps, pulse_on, pulse_off):
    print(f"[PHASE] {name} ({duration}s)")

    if name == "ATTACK":
        set_attack_flag(1)
        benign_traffic(net, duration)
        attack_traffic(net, duration, udp_bps, pulse_on, pulse_off)
    else:
        set_attack_flag(0)
        benign_traffic(net, duration)

    time.sleep(duration)


def stop_process(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()


def run_one(method, repeat, args):
    print(f"\n[RUN] {method} | Repeat {repeat}")

    results_file = Path(args.results_dir) / f"{method.lower()}_run{repeat}.csv"

    clean_environment()

    ml, ml_log = None, None
    ryu, ryu_log = None, None
    net = None

    try:
        ml, ml_log = start_ml(method, results_file, args.logs_dir)
        ryu, ryu_log = start_ryu(args.logs_dir)
        net = start_mininet()

        run_phase(net, "NORMAL_LOW", args.phase_a, args.udp_bps, args.pulse_on, args.pulse_off)
        run_phase(net, "NORMAL_DRIFT", args.phase_b, args.udp_bps, args.pulse_on, args.pulse_off)
        run_phase(net, "ATTACK", args.phase_c, args.udp_bps, args.pulse_on, args.pulse_off)
        run_phase(net, "RECOVERY", args.phase_d, args.udp_bps, args.pulse_on, args.pulse_off)

    finally:
        print("[STOP] Cleaning run")
        set_attack_flag(0)

        if net is not None:
            try:
                net.stop()
            except Exception:
                pass

        stop_process(ryu)
        stop_process(ml)

        if ml_log:
            ml_log.close()
        if ryu_log:
            ryu_log.close()

        sh("sudo mn -c || true")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=os.getcwd())
    p.add_argument("--results_dir", default=os.getcwd())
    p.add_argument("--logs_dir", default=os.path.join(os.getcwd(), "logs"))
    p.add_argument("--phase_a", type=int, default=30)
    p.add_argument("--phase_b", type=int, default=30)
    p.add_argument("--phase_c", type=int, default=30)
    p.add_argument("--phase_d", type=int, default=30)
    p.add_argument("--attack_pattern", default="udp_pulse")
    p.add_argument("--pulse_on", type=int, default=2)
    p.add_argument("--pulse_off", type=int, default=2)
    p.add_argument("--udp_bps", default="50M")
    p.add_argument("--methods", default="STATIC,GOMES2017,ARF_FIXED,PROPOSED")
    p.add_argument("--repeats", type=int, default=1)
    return p.parse_args()


def main():
    args = parse_args()

    os.chdir(args.root)
    Path(args.results_dir).mkdir(parents=True, exist_ok=True)
    Path(args.logs_dir).mkdir(parents=True, exist_ok=True)

    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]

    print("[INFO] Clean automated SDN experiment")
    print(f"[INFO] root={args.root}")
    print(f"[INFO] results_dir={args.results_dir}")
    print(f"[INFO] logs_dir={args.logs_dir}")
    print(f"[INFO] methods={methods}")
    print(f"[INFO] repeats={args.repeats}")
    print(f"[INFO] ATTACK_FLAG_FILE={ATTACK_FLAG_FILE}")

    for method in methods:
        for repeat in range(1, args.repeats + 1):
            run_one(method, repeat, args)

    print("[DONE] All runs completed")


if __name__ == "__main__":
    main()
