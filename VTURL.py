#!/usr/bin/env python3
"""
vt_url_check.py
Submit & poll URL analyses to VirusTotal v3.

Usage:
  export VIRUSTOTAL_API_KEY="..."
  python vt_url_check.py -f urls.txt --out vt_urls --delay 16 --max-poll 10
"""
from __future__ import annotations
import os, sys, time, argparse, csv, json, re
from datetime import datetime, timezone
import requests

API_BASE = "https://www.virustotal.com/api/v3"
_RE_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")

def load_api_key(cli_key: str|None) -> str:
    key = cli_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        raise RuntimeError("No API key. Provide --api-key or set VIRUSTOTAL_API_KEY env var.")
    return key.strip()

def vt_headers(key: str):
    return {"x-apikey": key, "Accept": "application/json"}

def submit_url(api_key: str, the_url: str) -> dict:
    r = requests.post(f"{API_BASE}/urls", headers=vt_headers(api_key), data={"url": the_url}, timeout=30)
    if r.status_code == 429:
        raise requests.HTTPError(response=r)
    r.raise_for_status()
    return r.json()

def fetch_analysis(api_key: str, analysis_id: str) -> dict:
    r = requests.get(f"{API_BASE}/analyses/{analysis_id}", headers=vt_headers(api_key), timeout=30)
    if r.status_code == 429:
        raise requests.HTTPError(response=r)
    r.raise_for_status()
    return r.json()

def fetch_url_object(api_key: str, url_id: str) -> dict:
    r = requests.get(f"{API_BASE}/urls/{url_id}", headers=vt_headers(api_key), timeout=30)
    if r.status_code == 429:
        raise requests.HTTPError(response=r)
    r.raise_for_status()
    return r.json()

def safe_sleep_for_retry(resp):
    retry = resp.headers.get("Retry-After")
    if retry:
        try:
            sec = int(retry)
            time.sleep(sec)
            return
        except Exception:
            pass
    time.sleep(20)

def detect_url(line: str) -> str|None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if _RE_URL.match(s):
        return s
    # try adding scheme if user gave domain only
    if "." in s and " " not in s:
        return "http://" + s
    return None

def main():
    p = argparse.ArgumentParser(description="VT URL submission & polling")
    p.add_argument("-f","--file", required=True, help="File with URLs (one per line)")
    p.add_argument("--api-key", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY)")
    p.add_argument("--out", default="vt_urls", help="Output prefix (csv/jsonl)")
    p.add_argument("--delay", type=float, default=16.0, help="Seconds between top-level submissions (default 16s)")
    p.add_argument("--max-poll", type=int, default=8, help="How many times to poll an analysis (sleep 3s between polls)")
    args = p.parse_args()

    api_key = load_api_key(args.api_key)
    if not os.path.exists(args.file):
        print("Input file not found:", args.file); sys.exit(1)

    items = []
    with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if ln.lower().startswith("http://") or ln.lower().startswith("https://") or ("." in ln and " " not in ln):
                items.append(ln)
            else:
                print("Skipping (not URL-like):", ln)

    total = len(items)
    print(f"Loaded {total} URLs")

    csv_path = f"{args.out}.csv"
    jsonl_path = f"{args.out}.jsonl"

    with open(csv_path, "w", newline="", encoding="utf-8") as cf, open(jsonl_path, "a", encoding="utf-8") as jf:
        writer = csv.DictWriter(cf, fieldnames=["url","timestamp","status","summary"])
        writer.writeheader()

        for i, u in enumerate(items, 1):
            print(f"[{i}/{total}] submit: {u}")
            ctx = {"url": u, "timestamp": datetime.now(timezone.utc).isoformat()}
            try:
                sub = submit_url(api_key, u)
                ctx["submission"] = sub
                # try to find analysis id
                analysis_id = sub.get("data", {}).get("id")
                url_id = sub.get("meta", {}).get("url") or None
                # poll analysis if we have analysis_id
                if analysis_id:
                    last_analysis = None
                    for poll in range(args.max_poll):
                        try:
                            a = fetch_analysis(api_key, analysis_id)
                            last_analysis = a
                            status = a.get("data", {}).get("attributes", {}).get("status")
                            if status == "completed":
                                ctx["result"] = a
                                break
                        except requests.HTTPError as he:
                            if he.response is not None and he.response.status_code == 429:
                                print(" 429 on poll, sleeping Retry-After...", end="", flush=True)
                                safe_sleep_for_retry(he.response)
                                continue
                            else:
                                raise
                        time.sleep(3)
                    if "result" not in ctx:
                        ctx["result"] = last_analysis or sub
                        ctx.setdefault("warnings", []).append("analysis polling timed out/unfinished")
                elif url_id:
                    try:
                        uo = fetch_url_object(api_key, url_id)
                        ctx["result"] = uo
                    except requests.HTTPError as he:
                        if he.response is not None and he.response.status_code == 429:
                            safe_sleep_for_retry(he.response)
                            uo = fetch_url_object(api_key, url_id)
                            ctx["result"] = uo
                        else:
                            raise
                else:
                    ctx["result"] = sub
                    ctx.setdefault("warnings", []).append("no analysis/url id returned")
                ctx["status"] = "ok"
                # summary (best-effort): try to pull positives if available
                res = ctx.get("result", {})
                data = res.get("data", {}) if isinstance(res, dict) else {}
                attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
                las = attrs.get("last_analysis_stats") or {}
                positives = las.get("malicious") if isinstance(las, dict) else None
                ctx["summary"] = f"malicious={positives}" if positives is not None else ""
                print(" done")
            except requests.HTTPError as he:
                if he.response is not None and he.response.status_code == 429:
                    print(" 429 on submit; honoring Retry-After...", end="", flush=True)
                    safe_sleep_for_retry(he.response)
                    ctx["status"] = "error"; ctx["error"] = "429 rate-limited on submit"
                    print(" continued")
                else:
                    ctx["status"] = "error"; ctx["error"] = f"HTTP {he.response.status_code if he.response else ''} {he}"
                    print(" error ->", ctx["error"])
            except Exception as e:
                ctx["status"] = "error"; ctx["error"] = str(e); print(" error ->", e)

            jf.write(json.dumps(ctx, ensure_ascii=False) + "\n")
            writer.writerow({"url": ctx.get("url"), "timestamp": ctx.get("timestamp"), "status": ctx.get("status"), "summary": ctx.get("summary","")})
            if i < total:
                time.sleep(args.delay)

    print("Done. CSV:", csv_path, "JSONL:", jsonl_path)

if __name__ == "__main__":
    main()
