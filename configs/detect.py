import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
LOG_FILE    = BASE_DIR / "logs"    / "auth.log"
RULES_FILE  = BASE_DIR / "configs" / "detection_rules.json"
REPORT_FILE = BASE_DIR / "reports" / "detection_report.json"
ALERTS_STREAM = REPORT_FILE.parent / "alerts.jsonl"  


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}
SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\b")

def parse_syslog_timestamp(line: str) -> str | None:
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    mon = MONTHS.get(m.group("mon"))
    day = int(m.group("day"))
    hh, mm, ss = map(int, m.group("time").split(":"))
    year = datetime.now().year  
    try:
        return datetime(year, mon, day, hh, mm, ss).isoformat()
    except Exception:
        return None

 
def load_rules():
    with RULES_FILE.open("r", encoding="utf-8") as f:
        rules = json.load(f)

    compiled = []
    for r in rules:
        rule = {
            "id": r["id"],
            "description": r.get("description", ""),
            "pattern": r["pattern"],
            "threshold": int(r.get("threshold", 1)),
            "type": r.get("type", "substring")  
        }
        if rule["type"] == "regex":
            rule["_re"] = re.compile(rule["pattern"])
        compiled.append(rule)
    return compiled

def read_log_lines():
    if not LOG_FILE.exists():
        print(f"[!] Missing log file: {LOG_FILE}")
        return []
    with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()

 
def run_detection(lines, rules):
    counters = defaultdict(int)
    last = {} 

    for line in lines:
        ts = parse_syslog_timestamp(line)
        for r in rules:
            if r["type"] == "regex":
                m = r["_re"].search(line)
                matched = m is not None
                captures = m.groupdict() if m else None
            else:
                matched = (r["pattern"] in line)
                captures = None

            if matched:
                counters[r["id"]] += 1
                last[r["id"]] = {"timestamp": ts, "line": line.strip(), "captures": captures}

    alerts = []
    for r in rules:
        rid = r["id"]
        count = counters.get(rid, 0)
        triggered = count >= r["threshold"]
        info = last.get(rid, {})
        alerts.append({
            "rule_id": rid,
            "description": r["description"],
            "pattern": r["pattern"],
            "type": r["type"],
            "threshold": r["threshold"],
            "match_count": count,
            "triggered": triggered,
            "last_seen": info.get("timestamp"),
            "last_match_sample": info.get("line"),
            "last_captures": info.get("captures"),
        })
    return alerts

def save_report(alerts):
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_FILE.open("w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

def append_alerts_stream(alerts):
    ALERTS_STREAM.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.utcnow().isoformat() + "Z"
    with ALERTS_STREAM.open("a", encoding="utf-8") as f:
        for a in alerts:
            rec = dict(a)
            rec["ingest_time"] = now
            f.write(json.dumps(rec) + "\n")


def main():
    if not RULES_FILE.exists():
        print(f"[!] Missing rules file: {RULES_FILE}")
        return
    rules = load_rules()
    lines = read_log_lines()
    alerts = run_detection(lines, rules)
    save_report(alerts)
    append_alerts_stream(alerts) 

    print("[+] Detection summary:")
    for a in alerts:
        flag = "ALERT" if a["triggered"] else "ok"
        print(f" - {a['rule_id']}: {a['match_count']}/{a['threshold']} -> {flag}")
    print(f"[+] Report saved to {REPORT_FILE}")
    print(f"[+] Stream appended: {ALERTS_STREAM}")

if __name__ == "__main__":
    main()
