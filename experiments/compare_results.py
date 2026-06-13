#!/usr/bin/env python3
import argparse
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt


METRICS = ["accuracy", "precision", "recall", "f1"]
METHOD_ORDER = ["STATIC", "GOMES2017", "ARF_FIXED", "PROPOSED"]


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Ensure numeric where possible
    for c in df.columns:
        if c in ["ts"]:
            continue
        df[c] = pd.to_numeric(df[c], errors="ignore")
    return df


def pick_method_name(path: Path, df: pd.DataFrame) -> str:
    # Prefer CSV 'mode' field; fallback to filename
    if "mode" in df.columns and df["mode"].notna().any():
        return str(df["mode"].dropna().iloc[0])
    return path.stem.upper()


def ensure_dir(d: Path):
    d.mkdir(parents=True, exist_ok=True)


def summarise_last_window(df: pd.DataFrame, window: int = 30) -> dict:
    # Use last N rows for stable summary
    tail = df.tail(window) if len(df) >= window else df
    out = {}
    for m in METRICS + ["tp", "tn", "fp", "fn", "fpr"]:
        if m in tail.columns:
            out[m] = float(pd.to_numeric(tail[m], errors="coerce").dropna().mean())
        else:
            out[m] = float("nan")
    out["rows"] = int(len(df))
    return out


def plot_metric(df: pd.DataFrame, method: str, metric: str, outdir: Path):
    if metric not in df.columns:
        return

    # Create an x-axis that starts near zero for nicer curves
    if "ts" in df.columns:
        t0 = df["ts"].iloc[0]
        x = df["ts"] - t0
        x_label = "time (s since start)"
    else:
        x = range(len(df))
        x_label = "sample index"

    y = pd.to_numeric(df[metric], errors="coerce")

    plt.figure()
    plt.plot(x, y)
    plt.ylim(0, 1)
    plt.xlabel(x_label)
    plt.ylabel(metric)
    plt.title(f"{method} — {metric}")
    plt.grid(True, alpha=0.3)

    out = outdir / f"{method.lower()}_{metric}.png"
    plt.tight_layout()
    plt.savefig(out, dpi=180)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csvs", nargs="+", help="Paths to method CSVs")
    ap.add_argument("--outdir", default="results/plots", help="Where to save plots")
    ap.add_argument("--summary_csv", default="results/summary_table.csv")
    ap.add_argument("--summary_md", default="results/summary_table.md")
    ap.add_argument("--window", type=int, default=30, help="Last-N window for summary")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    ensure_dir(outdir)

    rows = []
    data = {}  # method -> df

    for p in args.csvs:
        path = Path(p)
        df = load_csv(path)
        method = pick_method_name(path, df)
        data[method] = df

    # Plot 16 graphs (4 metrics x up to 4 methods)
    # Use desired order if present
    methods = [m for m in METHOD_ORDER if m in data] + [m for m in data.keys() if m not in METHOD_ORDER]

    for method in methods:
        df = data[method]
        for metric in METRICS:
            plot_metric(df, method, metric, outdir)

        # Summary per method
        s = summarise_last_window(df, window=args.window)
        s["method"] = method
        rows.append(s)

    summary = pd.DataFrame(rows)
    # Nice ordering
    summary = summary[["method", "rows", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1", "fpr"]]
    summary = summary.sort_values("method", key=lambda col: col.map({m:i for i,m in enumerate(methods)}).fillna(999))

    Path(args.summary_csv).parent.mkdir(parents=True, exist_ok=True)
    summary.to_csv(args.summary_csv, index=False)

    # Markdown table for supervisor-friendly paste
    md = summary.copy()
    for c in ["accuracy", "precision", "recall", "f1", "fpr"]:
        md[c] = md[c].map(lambda v: f"{v:.3f}" if pd.notna(v) else "")
    for c in ["tp","tn","fp","fn","rows"]:
        md[c] = md[c].map(lambda v: f"{int(round(v))}" if pd.notna(v) else "")
    md_text = md.to_markdown(index=False)

    Path(args.summary_md).write_text(md_text + "\n")
    print(f"[OK] Plots saved in: {outdir}")
    print(f"[OK] Summary CSV: {args.summary_csv}")
    print(f"[OK] Summary MD : {args.summary_md}")
    print("\n--- Summary Table ---\n")
    print(md_text)


if __name__ == "__main__":
    main()

