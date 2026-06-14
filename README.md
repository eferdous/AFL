# AFL: Adaptive Feedback Learning for SDN Anomaly Detection

This repository implements an Adaptive Feedback Learning framework for SDN anomaly detection using Mininet, Open vSwitch, Ryu, OpenFlow statistics, and adaptive Random Forest-style learning.

## Purpose

The aim is to detect anomalies in SDN traffic and adapt the detector when traffic behaviour changes over time.

The system compares:

- STATIC baseline
- GOMES2017-style adaptive threshold baseline
- ARF_FIXED baseline
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
