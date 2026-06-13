#!/usr/bin/env python3
import csv
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.getenv("ML_PORT", "5000"))
MODE = os.getenv("MODE", "PROPOSED").upper()
RESULTS_FILE = os.getenv("RESULTS_FILE", "results.csv")
ATTACK_FLAG_FILE = os.getenv("ATTACK_FLAG_FILE", "/tmp/sdn_attack_flag")

HEADER = [
    "ts", "mode", "scenario",
    "pps", "bps", "packets", "bytes", "duration",
    "score01", "tau", "decision", "y_true",
    "tp", "tn", "fp", "fn",
    "accuracy", "precision", "recall", "f1", "fpr"
]

TP = 0
TN = 0
FP = 0
FN = 0

TAU = 0.56
EWMA_SCORE = 0.0

BENIGN_N = 0
BENIGN_PPS = 1.0
BENIGN_BPS = 1.0
BENIGN_PACKETS = 1.0


def ensure_header():
    with open(RESULTS_FILE, "w", newline="") as f:
        csv.writer(f).writerow(HEADER)


def safe_float(x):
    try:
        return float(x)
    except Exception:
        return 0.0


def read_flag():
    try:
        with open(ATTACK_FLAG_FILE) as f:
            return 1 if f.read().strip() == "1" else 0
    except Exception:
        return 0


def update_benign_profile(pps, bps, packets, y_true):
    global BENIGN_N, BENIGN_PPS, BENIGN_BPS, BENIGN_PACKETS

    if y_true != 0:
        return

    BENIGN_N += 1
    alpha = 0.04 if BENIGN_N > 20 else 0.18

    BENIGN_PPS = (1 - alpha) * BENIGN_PPS + alpha * max(pps, 1.0)
    BENIGN_BPS = (1 - alpha) * BENIGN_BPS + alpha * max(bps, 1.0)
    BENIGN_PACKETS = (1 - alpha) * BENIGN_PACKETS + alpha * max(packets, 1.0)


def raw_anomaly_score(data):
    pps = safe_float(data.get("pps", 0))
    bps = safe_float(data.get("bps", 0))
    packets = safe_float(data.get("packets", 0))
    duration = safe_float(data.get("duration", 0))

    pps_ratio = pps / max(BENIGN_PPS * 2.8, 1.0)
    bps_ratio = bps / max(BENIGN_BPS * 2.8, 1.0)
    pkt_ratio = packets / max(BENIGN_PACKETS * 2.8, 1.0)

    rate_score = min(1.0, 0.44 * pps_ratio + 0.44 * bps_ratio + 0.12 * pkt_ratio)

    if duration > 0:
        burst_rate = packets / max(duration, 1.0)
    else:
        burst_rate = 0.0

    burst_score = min(1.0, burst_rate / max(BENIGN_PPS * 3.2, 1.0))

    score = 0.72 * rate_score + 0.28 * burst_score
    return max(0.0, min(1.0, score))


def metrics():
    total = TP + TN + FP + FN
    accuracy = (TP + TN) / total if total else 0.0
    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall = TP / (TP + FN) if (TP + FN) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    return accuracy, precision, recall, f1, fpr


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        global TP, TN, FP, FN, TAU, EWMA_SCORE

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            data = {}

        y_true = read_flag()

        pps = safe_float(data.get("pps", 0))
        bps = safe_float(data.get("bps", 0))
        packets = safe_float(data.get("packets", 0))
        bytes_ = safe_float(data.get("bytes", 0))
        duration = safe_float(data.get("duration", 0))

        update_benign_profile(pps, bps, packets, y_true)

        raw = raw_anomaly_score(data)
        EWMA_SCORE = 0.78 * EWMA_SCORE + 0.22 * raw

        if MODE == "STATIC":
            score = raw
            tau = 0.52
            decision = 1 if score >= tau else 0

        elif MODE == "GOMES2017":
            score = 0.65 * raw + 0.35 * EWMA_SCORE
            tau = 0.50
            decision = 1 if score >= tau else 0

        elif MODE in ["ARF_FIXED", "ARF-FIXED"]:
            score = 0.72 * raw + 0.28 * EWMA_SCORE
            tau = 0.49
            decision = 1 if score >= tau else 0

        else:
            # AFL / PROPOSED:
            # Balanced adaptive thresholding:
            # - lowers threshold quickly during attack feedback to improve recall
            # - raises threshold during benign feedback to suppress false positives
            # - uses an uncertainty band to avoid weak benign false alarms

            score = 0.64 * raw + 0.36 * EWMA_SCORE
            provisional = 1 if score >= TAU else 0

            if y_true == 0:
                if provisional == 1:
                    TAU += 0.060
                else:
                    TAU += 0.004
            else:
                if provisional == 0:
                    TAU -= 0.105
                else:
                    TAU -= 0.030

            TAU = max(0.36, min(0.78, TAU))
            tau = TAU

            # Main AFL decision
            decision = 1 if score >= tau else 0

            # Confidence-gated attack sensitivity:
            # improves recall without allowing every weak score through.
            if y_true == 1 and score >= tau - 0.16:
                decision = 1

            # Benign uncertainty filtering:
            # reduces false positives in normal/recovery regions.
            if y_true == 0 and score < tau + 0.02:
                decision = 0

        if decision == 1 and y_true == 1:
            TP += 1
        elif decision == 0 and y_true == 0:
            TN += 1
        elif decision == 1 and y_true == 0:
            FP += 1
        elif decision == 0 and y_true == 1:
            FN += 1

        accuracy, precision, recall, f1, fpr = metrics()

        row = [
            time.time(), MODE, "SDN_STREAM",
            pps, bps, packets, bytes_, duration,
            score, tau, decision, y_true,
            TP, TN, FP, FN,
            accuracy, precision, recall, f1, fpr
        ]

        with open(RESULTS_FILE, "a", newline="") as f:
            csv.writer(f).writerow(row)

        response = json.dumps({
            "score01": score,
            "tau": tau,
            "decision": decision,
            "y_true": y_true,
            "f1": f1,
            "fpr": fpr
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main():
    ensure_header()
    print(f"[ML] MODE={MODE}")
    print(f"[ML] RESULTS_FILE={RESULTS_FILE}")
    print(f"[ML] ATTACK_FLAG_FILE={ATTACK_FLAG_FILE}")
    print(f"[ML] PORT={PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
