#!/bin/bash
cd "$(dirname "$0")"

rm -rf results/run_short
mkdir -p results/run_short logs

sudo pkill -f ryu.cmd.manager 2>/dev/null || true
sudo pkill -f ml_service.py 2>/dev/null || true
sudo mn -c
sudo service openvswitch-switch restart

sudo -E env "PATH=$PATH" EVENTLET_NO_GREENDNS=yes python3 -u experiments/experiment_runner.py \
  --root "$PWD" \
  --results_dir "$PWD/results/run_short" \
  --logs_dir "$PWD/logs" \
  --methods STATIC,GOMES2017,ARF_FIXED,PROPOSED \
  --repeats 1 \
  --phase_a 30 \
  --phase_b 30 \
  --phase_c 30 \
  --phase_d 30 \
  --attack_pattern udp_pulse \
  --pulse_on 2 \
  --pulse_off 2 \
  --udp_bps 50M

python3 experiments/compare_results.py \
  results/run_short/static_run1.csv \
  results/run_short/gomes2017_run1.csv \
  results/run_short/arf_fixed_run1.csv \
  results/run_short/proposed_run1.csv \
  --outdir results/run_short/plots \
  --summary_csv results/run_short/summary_table.csv \
  --summary_md results/run_short/summary_table.md

cat results/run_short/summary_table.md
