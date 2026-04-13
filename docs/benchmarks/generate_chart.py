#!/usr/bin/env python3
"""Generate SVG benchmark charts from results.json."""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_results():
    with open(os.path.join(SCRIPT_DIR, "results.json")) as f:
        return json.load(f)

def generate_latency_svg(data):
    """Multi-bar grouped chart: avg, p50, p95, p99 per packet size."""
    results = data["results"]
    sizes = [r["size"] for r in results]

    # Chart dimensions
    W, H = 800, 420
    margin = {"top": 60, "right": 30, "bottom": 80, "left": 65}
    chart_w = W - margin["left"] - margin["right"]
    chart_h = H - margin["top"] - margin["bottom"]

    # Data series
    series = [
        ("avg",  "#3b82f6", "Avg"),
        ("p50",  "#22c55e", "P50"),
        ("p95",  "#f59e0b", "P95"),
        ("p99",  "#ef4444", "P99"),
    ]

    max_val = max(r["p99"] for r in results) * 1.15
    n_groups = len(sizes)
    n_bars = len(series)
    group_w = chart_w / n_groups
    bar_w = group_w * 0.7 / n_bars
    gap = group_w * 0.3

    def y(val):
        return margin["top"] + chart_h - (val / max_val * chart_h)

    svg_parts = []
    svg_parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui,-apple-system,sans-serif">')

    # Background
    svg_parts.append(f'<rect width="{W}" height="{H}" fill="#0d1117" rx="12"/>')

    # Title
    svg_parts.append(f'<text x="{W/2}" y="28" text-anchor="middle" fill="#e6edf3" font-size="16" font-weight="600">UDP Round-Trip Latency by Packet Size</text>')
    svg_parts.append(f'<text x="{W/2}" y="48" text-anchor="middle" fill="#7d8590" font-size="11">OVH VPS (Gravelines) ↔ Home Server (Paris) via WireGuard | 200 packets/size</text>')

    # Grid lines
    grid_steps = [0, 3, 6, 9, 12, 15]
    for v in grid_steps:
        if v > max_val:
            continue
        yv = y(v)
        svg_parts.append(f'<line x1="{margin["left"]}" y1="{yv}" x2="{W - margin["right"]}" y2="{yv}" stroke="#21262d" stroke-width="1"/>')
        svg_parts.append(f'<text x="{margin["left"] - 8}" y="{yv + 4}" text-anchor="end" fill="#7d8590" font-size="11">{v}ms</text>')

    # Y-axis label
    svg_parts.append(f'<text x="14" y="{margin["top"] + chart_h/2}" text-anchor="middle" fill="#7d8590" font-size="11" transform="rotate(-90 14 {margin["top"] + chart_h/2})">Latency (ms)</text>')

    # Bars
    for gi, r in enumerate(results):
        group_x = margin["left"] + gi * group_w + gap / 2

        for bi, (key, color, _) in enumerate(series):
            val = r[key]
            bx = group_x + bi * bar_w
            by = y(val)
            bh = y(0) - by

            # Bar with rounded top
            svg_parts.append(f'<rect x="{bx}" y="{by}" width="{bar_w - 2}" height="{bh}" fill="{color}" opacity="0.85" rx="3" ry="3"/>')

            # Value label on bar
            if bi == 0:  # Only show avg value to avoid clutter
                svg_parts.append(f'<text x="{group_x + (n_bars * bar_w) / 2}" y="{by - 6}" text-anchor="middle" fill="#e6edf3" font-size="10" font-weight="500">{val:.1f}ms</text>')

        # X-axis label
        svg_parts.append(f'<text x="{group_x + (n_bars * bar_w) / 2}" y="{margin["top"] + chart_h + 20}" text-anchor="middle" fill="#c9d1d9" font-size="12" font-weight="500">{r["size"]}B</text>')

    # Legend
    legend_y = H - 25
    legend_x_start = W / 2 - 160
    for i, (_, color, label) in enumerate(series):
        lx = legend_x_start + i * 80
        svg_parts.append(f'<rect x="{lx}" y="{legend_y - 8}" width="12" height="12" fill="{color}" opacity="0.85" rx="2"/>')
        svg_parts.append(f'<text x="{lx + 16}" y="{legend_y + 2}" fill="#c9d1d9" font-size="11">{label}</text>')

    # Baseline marker
    baseline = data["meta"]["baseline_icmp_ms"]
    by_base = y(baseline)
    svg_parts.append(f'<line x1="{margin["left"]}" y1="{by_base}" x2="{W - margin["right"]}" y2="{by_base}" stroke="#8b5cf6" stroke-width="1.5" stroke-dasharray="6 4"/>')
    svg_parts.append(f'<text x="{W - margin["right"] - 4}" y="{by_base - 6}" text-anchor="end" fill="#8b5cf6" font-size="10">ICMP baseline {baseline}ms</text>')

    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def generate_jitter_svg(data):
    """Jitter + loss sparkline chart."""
    results = data["results"]

    W, H = 800, 280
    margin = {"top": 55, "right": 30, "bottom": 70, "left": 65}
    chart_w = W - margin["left"] - margin["right"]
    chart_h = H - margin["top"] - margin["bottom"]

    max_jitter = max(r["jitter"] for r in results) * 1.6
    n = len(results)
    bar_w = chart_w / n * 0.5

    def y(val):
        return margin["top"] + chart_h - (val / max_jitter * chart_h)

    svg = []
    svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui,-apple-system,sans-serif">')
    svg.append(f'<rect width="{W}" height="{H}" fill="#0d1117" rx="12"/>')
    svg.append(f'<text x="{W/2}" y="28" text-anchor="middle" fill="#e6edf3" font-size="16" font-weight="600">Jitter &amp; Packet Loss</text>')
    svg.append(f'<text x="{W/2}" y="46" text-anchor="middle" fill="#7d8590" font-size="11">Standard deviation of RTT | Loss rate per packet size</text>')

    # Grid
    for v in [0, 0.25, 0.5, 0.75, 1.0]:
        if v > max_jitter:
            continue
        yv = y(v)
        svg.append(f'<line x1="{margin["left"]}" y1="{yv}" x2="{W - margin["right"]}" y2="{yv}" stroke="#21262d"/>')
        svg.append(f'<text x="{margin["left"] - 8}" y="{yv + 4}" text-anchor="end" fill="#7d8590" font-size="11">{v:.2f}ms</text>')

    svg.append(f'<text x="14" y="{margin["top"] + chart_h/2}" text-anchor="middle" fill="#7d8590" font-size="11" transform="rotate(-90 14 {margin["top"] + chart_h/2})">Jitter (ms)</text>')

    for i, r in enumerate(results):
        cx = margin["left"] + (i + 0.5) * chart_w / n
        bx = cx - bar_w / 2

        # Jitter bar
        jy = y(r["jitter"])
        jh = y(0) - jy
        svg.append(f'<rect x="{bx}" y="{jy}" width="{bar_w}" height="{jh}" fill="#a78bfa" opacity="0.8" rx="3"/>')
        svg.append(f'<text x="{cx}" y="{jy - 6}" text-anchor="middle" fill="#c4b5fd" font-size="10" font-weight="500">{r["jitter"]:.2f}ms</text>')

        # Loss badge
        loss_pct = r["lost"] / r["sent"] * 100
        badge_color = "#22c55e" if loss_pct == 0 else ("#f59e0b" if loss_pct < 5 else "#ef4444")
        badge_text = "0%" if loss_pct == 0 else f"{loss_pct:.1f}%"
        svg.append(f'<text x="{cx}" y="{margin["top"] + chart_h + 20}" text-anchor="middle" fill="#c9d1d9" font-size="12" font-weight="500">{r["size"]}B</text>')
        svg.append(f'<rect x="{cx - 18}" y="{margin["top"] + chart_h + 28}" width="36" height="18" fill="{badge_color}" opacity="0.2" rx="9"/>')
        svg.append(f'<text x="{cx}" y="{margin["top"] + chart_h + 41}" text-anchor="middle" fill="{badge_color}" font-size="10" font-weight="600">{badge_text}</text>')

    # Legend
    svg.append(f'<rect x="{W/2 - 80}" y="{H - 22}" width="10" height="10" fill="#a78bfa" opacity="0.8" rx="2"/>')
    svg.append(f'<text x="{W/2 - 66}" y="{H - 13}" fill="#c9d1d9" font-size="11">Jitter (stddev)</text>')
    svg.append(f'<text x="{W/2 + 40}" y="{H - 13}" fill="#7d8590" font-size="11">Badges = packet loss</text>')

    svg.append('</svg>')
    return '\n'.join(svg)


def generate_overview_svg(data):
    """Single summary card with key metrics."""
    meta = data["meta"]
    results = data["results"]

    avg_latency = sum(r["avg"] for r in results) / len(results)
    avg_jitter = sum(r["jitter"] for r in results) / len(results)
    total_lost = sum(r["lost"] for r in results)
    total_sent = sum(r["sent"] for r in results)
    loss_pct = total_lost / total_sent * 100
    worst_p99 = max(r["p99"] for r in results)

    W, H = 800, 160
    svg = []
    svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui,-apple-system,sans-serif">')
    svg.append(f'<rect width="{W}" height="{H}" fill="#0d1117" rx="12"/>')
    svg.append(f'<rect x="1" y="1" width="{W-2}" height="{H-2}" fill="none" stroke="#30363d" rx="12"/>')

    # Metrics
    metrics = [
        ("Avg Latency", f"{avg_latency:.1f}ms", "#3b82f6"),
        ("P99 (worst)", f"{worst_p99:.1f}ms", "#ef4444"),
        ("Jitter", f"{avg_jitter:.2f}ms", "#a78bfa"),
        ("Packet Loss", f"{loss_pct:.1f}%", "#22c55e" if loss_pct < 1 else "#f59e0b"),
    ]

    col_w = W / len(metrics)
    for i, (label, value, color) in enumerate(metrics):
        cx = col_w * i + col_w / 2
        svg.append(f'<text x="{cx}" y="50" text-anchor="middle" fill="{color}" font-size="32" font-weight="700">{value}</text>')
        svg.append(f'<text x="{cx}" y="72" text-anchor="middle" fill="#7d8590" font-size="12">{label}</text>')

    # Route info
    svg.append(f'<text x="{W/2}" y="105" text-anchor="middle" fill="#c9d1d9" font-size="13">{meta["server_location"]} ↔ {meta["agent_location"]}</text>')
    svg.append(f'<text x="{W/2}" y="125" text-anchor="middle" fill="#7d8590" font-size="11">WireGuard tunnel | {total_sent} packets | ICMP baseline {meta["baseline_icmp_ms"]}ms</text>')
    svg.append(f'<text x="{W/2}" y="145" text-anchor="middle" fill="#484f58" font-size="10">{meta["date"]}</text>')

    svg.append('</svg>')
    return '\n'.join(svg)


if __name__ == "__main__":
    data = load_results()

    charts = {
        "latency.svg": generate_latency_svg,
        "jitter.svg": generate_jitter_svg,
        "overview.svg": generate_overview_svg,
    }

    for filename, generator in charts.items():
        path = os.path.join(SCRIPT_DIR, filename)
        svg = generator(data)
        with open(path, "w") as f:
            f.write(svg)
        print(f"  {filename}")

    print("Done.")
