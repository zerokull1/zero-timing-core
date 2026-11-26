#!/usr/bin/env python3
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
# Smart Adaptive Multi-WAN Baton & Bonding Controller
import re, subprocess, time

TARGETS = ["77.88.8.8", "9.9.9.9", "1.1.1.1"]
ema_eff = {}
active_baton = None

def get_gateways():
    out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True)
    gws = {}
    for line in out.splitlines():
        if "default via" in line and "proto static" not in line:
            parts = line.split()
            gw = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            if dev not in gws:
                gws[dev] = gw
    return gws

def probe_dev(dev):
    for tgt in TARGETS:
        res = subprocess.run(
            ["ping", "-I", dev, "-c", "4", "-i", "0.15", "-W", "1", "-q", tgt],
            capture_output=True, text=True
        )
        m_loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", res.stdout)
        m_rtt = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/([\d.]+)", res.stdout)
        loss = float(m_loss.group(1)) if m_loss else 100.0
        rtt = float(m_rtt.group(1)) if m_rtt else 999.0
        jitter = float(m_rtt.group(2)) if m_rtt else 500.0
        if loss < 100.0:
            return loss, rtt, jitter
    return 100.0, 999.0, 500.0

last_state = None
while True:
    gws = get_gateways()
    if gws:
        stats = []
        for dev, gw in sorted(gws.items()):
            loss, rtt, jitter = probe_dev(dev)
            raw_eff = rtt + (2.5 * jitter) + (loss * 25.0)
            prev = ema_eff.get(dev, raw_eff)
            # Быстрая реакция на ухудшение (0.75), плавный возврат (0.45)
            alpha = 0.75 if raw_eff > prev else 0.45
            eff = alpha * raw_eff + (1.0 - alpha) * prev
            ema_eff[dev] = eff
            healthy = (loss == 0.0 and jitter < 40.0 and rtt < 180.0)
            stats.append((dev, gw, loss, rtt, jitter, eff, healthy))

        # Сортируем от лучшего (минимальный eff) к худшему
        stats.sort(key=lambda x: x[5])
        best = stats[0]

        # Гистерезис переключения эстафеты (15% порог против дребезга)
        if active_baton and active_baton != best[0]:
            cur_obj = next((s for s in stats if s[0] == active_baton), None)
            if cur_obj and cur_obj[6] and cur_obj[5] <= best[5] * 1.15:
                best = cur_obj
        active_baton = best[0]

        nexthops = []
        if len(stats) == 1:
            d, g, l, r, j, e, h = stats[0]
            nexthops.append((g, d, 16, r, j, l, "SOLO"))
        else:
            second = stats[1]
            # Если лучший канал стабилен, а второй просел (потери, джиттер или >1.5x хуже) -> ПОЛНАЯ ПЕРЕДАЧА ЭСТАФЕТЫ
            if best[6] and (not second[6] or second[5] > best[5] * 1.5):
                nexthops.append((best[1], best[0], 64, best[3], best[4], best[2], "BATON-MASTER"))
                if second[2] < 100.0:
                    nexthops.append((second[1], second[0], 1, second[3], second[4], second[2], "STANDBY"))
            else:
                # Оба канала ровные -> пропорциональная агрегация
                for d, g, l, r, j, e, h in stats:
                    w = 1 if l >= 100.0 else max(2, min(32, int(round(2000.0 / max(e, 20.0)))))
                    nexthops.append((g, d, w, r, j, l, "BOND"))

        state_sig = [(g, d, w) for g, d, w, _, _, _, _ in nexthops]
        if state_sig != last_state:
            cmd = ["ip", "route", "replace", "default", "scope", "global", "proto", "static"]
            for g, d, w, _, _, _, _ in nexthops:
                cmd += ["nexthop", "via", g, "dev", d, "weight", str(w)]
            subprocess.run(cmd, stderr=subprocess.DEVNULL)
            last_state = state_sig
            info = " | ".join(f"{d}[{st}]: w={w} (rtt={r:.1f}ms, jit={j:.1f}ms, loss={l:.0f}%)" for _, d, w, r, j, l, st in nexthops)
            print(f"[MULTIWAN-BATON] Active={active_baton} -> {info}", flush=True)
    time.sleep(2.5)
