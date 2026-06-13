# paste the full code above, save, exit
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flow_exporter.py (drop-in replacement)

Purpose:
- Poll OpenFlow stats from switches (OF1.3)
- Build simple aggregate features (pps, bps, packets, bytes, duration)
- POST JSON to ML service (ML_URL) using stdlib urllib (NO requests)

Environment variables:
- ML_URL        (default: http://127.0.0.1:5000/score)
- POLL_INTERVAL (default: 1.0 seconds)

Run (example):
  EVENTLET_NO_GREENDNS=yes POLL_INTERVAL=1.0 ML_URL=http://127.0.0.1:5000/score \
    ryu-manager ryu.app.simple_switch_13 controller/flow_exporter.py --ofp-tcp-listen-port 6653
"""

import os
import time
import json
import urllib.request
import urllib.error

# Safer with eventlet/ryu environments
os.environ.setdefault("EVENTLET_NO_GREENDNS", "yes")

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


ML_URL = os.getenv("ML_URL", "http://127.0.0.1:5000/score").strip()
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.0"))


def post_json(url: str, payload: dict, timeout: float = 2.0):
    """POST JSON payload using urllib (no requests dependency)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        # Server responded with HTTP error code
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = str(e)
        return e.code, body
    except urllib.error.URLError as e:
        return None, f"URLError: {e}"
    except Exception as e:
        return None, f"Exception: {e}"


class FlowExporter(app_manager.RyuApp):
    """
    Minimal stats exporter:
    - tracks datapaths
    - periodically requests flow stats
    - aggregates packet/byte totals across flows
    - computes deltas per interval => pps/bps
    - posts to ML_URL
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowExporter, self).__init__(*args, **kwargs)
        self.datapaths = {}  # dpid -> datapath
        self._monitor_thread = hub.spawn(self._monitor)

        # Per-switch last totals to compute deltas
        # dpid -> {"t": last_ts, "packets": last_packets, "bytes": last_bytes}
        self.last_totals = {}

        self.logger.info("[Exporter] ML_URL=%s POLL_INTERVAL=%.3fs", ML_URL, POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        dpid = dp.id
        if ev.state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                self.datapaths[dpid] = dp
                self.logger.info("[Exporter] Register datapath: dpid=%s", dpid)
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                del self.datapaths[dpid]
                self.logger.info("[Exporter] Unregister datapath: dpid=%s", dpid)

    def _monitor(self):
        while True:
            try:
                for dp in list(self.datapaths.values()):
                    self._request_flow_stats(dp)
                hub.sleep(POLL_INTERVAL)
            except Exception as e:
                self.logger.exception("[Exporter] Monitor loop error: %s", e)
                hub.sleep(1.0)

    def _request_flow_stats(self, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id

        # Aggregate across all flows except table-miss (optional filter)
        total_packets = 0
        total_bytes = 0

        for stat in ev.msg.body:
            # stat is OFPFlowStats
            # You can filter table-miss (priority 0) to reduce noise
            # if hasattr(stat, "priority") and stat.priority == 0:
            #     continue
            total_packets += int(getattr(stat, "packet_count", 0))
            total_bytes += int(getattr(stat, "byte_count", 0))

        now = time.time()
        last = self.last_totals.get(dpid)

        if last is None:
            # First observation: initialize; can't compute deltas yet
            self.last_totals[dpid] = {"t": now, "packets": total_packets, "bytes": total_bytes}
            self.logger.info("[Exporter] Init totals dpid=%s packets=%d bytes=%d", dpid, total_packets, total_bytes)
            return

        dt = max(now - last["t"], 1e-6)
        dpkts = max(total_packets - last["packets"], 0)
        dbytes = max(total_bytes - last["bytes"], 0)

        pps = dpkts / dt
        bps = (dbytes * 8.0) / dt

        payload = {
            "ts": now,
            "dpid": int(dpid),
            "duration": float(dt),
            "packets": int(dpkts),
            "bytes": int(dbytes),
            "pps": float(pps),
            "bps": float(bps),
            # helpful tags for your logs/CSV if ML stores them
            "source": "ryu_flow_exporter",
        }

        code, body = post_json(ML_URL, payload, timeout=2.0)

        # Update last totals
        self.last_totals[dpid] = {"t": now, "packets": total_packets, "bytes": total_bytes}

        # Log response (ML service may return JSON)
        if code is None:
            self.logger.warning("[Exporter] ML POST failed dpid=%s err=%s", dpid, body)
            return

        # Try parse JSON response
        resp_obj = None
        try:
            resp_obj = json.loads(body)
        except Exception:
            resp_obj = None

        if resp_obj is not None:
            self.logger.info("[Exporter] dpid=%s pps=%.2f bps=%.2f -> ML(%s): %s",
                             dpid, pps, bps, code, resp_obj)
        else:
            self.logger.info("[Exporter] dpid=%s pps=%.2f bps=%.2f -> ML(%s): %s",
                             dpid, pps, bps, code, body)

