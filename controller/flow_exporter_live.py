#!/usr/bin/env python3
import os, time, json
import urllib.request
import urllib.error

RYU_HOST = "127.0.0.1"
RYU_PORT = 8080

ML_HOST  = "127.0.0.1"
ML_PORT  = 5000

POLL_SECS = 1.0

def http_get_json(url):
    with urllib.request.urlopen(url, timeout=2.5) as r:
        data = r.read().decode("utf-8")
    return json.loads(data) if data.strip() else None

def http_post_json(url, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=2.5) as r:
        return r.read()

def ryu_url(path):
    return f"http://{RYU_HOST}:{RYU_PORT}{path}"

def ml_url(path):
    return f"http://{ML_HOST}:{ML_PORT}{path}"

def get_dpid():
    sw = http_get_json(ryu_url("/stats/switches"))
    if not sw:
        return None
    return str(sw[0])

def get_port_totals(dpid):
    data = http_get_json(ryu_url(f"/stats/port/{dpid}"))
    if not data:
        return None
    rows = data.get(str(dpid))
    if not rows:
        return None

    pkts = 0
    byt  = 0
    for r in rows:
        if r.get("port_no") == "LOCAL":
            continue
        pkts += int(r.get("rx_packets", 0)) + int(r.get("tx_packets", 0))
        byt  += int(r.get("rx_bytes", 0)) + int(r.get("tx_bytes", 0))

    return pkts, byt

def main():
    print("[EXPORTER] Waiting for Ryu...", flush=True)
    while True:
        try:
            dpid = get_dpid()
            if dpid:
                print(f"[EXPORTER] Found switch dpid={dpid}", flush=True)
                break
        except Exception:
            pass
        time.sleep(1)

    prev = None
    prev_t = None

    while True:
        try:
            totals = get_port_totals(dpid)
            now = time.time()
            if not totals:
                time.sleep(POLL_SECS)
                continue

            pkts, byt = totals

            if prev is None:
                prev = (pkts, byt)
                prev_t = now
                time.sleep(POLL_SECS)
                continue

            dt = now - prev_t
            dpkts = pkts - prev[0]
            dbyt  = byt - prev[1]

            payload = {
                "ts": now,
                "pps": dpkts / dt if dt > 0 else 0,
                "bps": (dbyt * 8) / dt if dt > 0 else 0,
                "packets": dpkts,
                "bytes": dbyt,
                "duration": dt,
            }

            http_post_json(ml_url("/score"), payload)
            print(f"[EXPORTER] Sent sample pps={payload['pps']:.2f}", flush=True)

            prev = (pkts, byt)
            prev_t = now
            time.sleep(POLL_SECS)

        except Exception as e:
            print("[EXPORTER] Error:", e, flush=True)
            time.sleep(1)

if __name__ == "__main__":
    main()
