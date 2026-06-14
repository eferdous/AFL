# AFL: Adaptive Feedback Learning for SDN Anomaly Detection

This repository implements an Adaptive Feedback Learning framework for SDN anomaly detection using Mininet, Open vSwitch, Ryu, OpenFlow statistics, and adaptive Random Forest-style learning.

## Purpose

The aim is to detect anomalies in SDN traffic and adapt the detector when traffic behaviour changes over time.

The system compares:

- OnlineIDS2024 baseline
- AdaptiveRF2024 baseline
- StreamRF2025 baseline
- PROPOSED AFL method

## Architecture

```text
Mininet Hosts
   ↓
Open vSwitch
   ↓
Ryu Controller
   ↓
OpenFlow Statistics
   ↓
Feature Extraction
   ↓
Machine Learning Detector
   ↓
Prediction, Feedback, Buffer, Adaptation

## Updated comparison methods

In the latest paper version, the proposed AFL method is compared with the following recent streaming IDS and adaptive forest baselines:

- OnlineIDS2024
- AdaptiveRF2024
- StreamRF2025
- Proposed AFL method

The previous placeholder/baseline names such as STATIC, Gomes/GOMES2017, and ARF_FIXED have been removed from the documentation.
