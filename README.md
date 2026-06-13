# AFL-ARF Adaptive SDN Intrusion Detection Framework

This repository contains the implementation of an Adaptive Feedback Learning framework for SDN anomaly detection.

## Methods

- STATIC
- GOMES2017
- ARF_FIXED
- PROPOSED AFL

## Training Data

Initial calibration uses controlled Mininet-generated benign and attack traffic.

Benign traffic:
- ping
- TCP iperf
- normal host communication

Attack traffic:
- UDP flood
- ping flood
- port scan
- mixed attack bursts

## Test Data

After calibration, mixed streaming traffic is generated in Mininet. Ryu exports OpenFlow statistics to the ML service. The model writes:

- decision = 0 benign
- decision = 1 anomaly

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-pip mininet openvswitch-switch iperf nmap hping3 git
python3 -m pip install --user -r requirements.txt
