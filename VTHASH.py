#!/usr/bin/env python3
"""
vt_hash_check.py
Bulk VirusTotal file-hash lookups (md5/sha1/sha256).

Usage:
  export VIRUSTOTAL_API_KEY="..."
  python vt_hash_check.py -f hashes.txt --out vt_hashes --delay 16
"""
from __future__ import annotations
import os, sys, time, argparse, csv, json, re
from datetime import datetime, timezone
import requests

API_BASE = "https://www.virustotal.com/api/v3"
_RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_RE_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

def load_api_key(cli_key: str|None) -> str:
    key = cli_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        raise RuntimeError("No API key. Provide --api-key or set VIRUSTOTAL_API_KEY env var.")
    return key.strip()

def vt_headers(key: str):
    return {"x-apikey": key, "Accept": "application/json"}

def fetch_hash(api_key: str, h: str) -> dict:
    url = f"{API_BASE}/files/{h}"
    r = requests.get(url, headers=vt_headers(api_key), timeout=30)
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

def main():
    p = argparse.ArgumentParser(description="Bulk VT file-hash lookups")
    p.add_argument("-f","--file", required=True, help="File with hashes (one per line)")
    p.add_argument("--api-key", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY)")
    p.add_argument("--out", default="vt_hashes", help="Output prefix (csv/jsonl)")
    p.add_argument("--delay", type=float, default=16.0, help="Seconds between requests (default 16s)")
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
            if _RE_SHA256.match(ln) or _RE_SHA1.match(ln) or _RE_MD5.match(ln):
                items.append(ln)
            else:
                print("Skipping invalid hash:", ln)

    total = len(items)
    print(f"Loaded {total} hashes")

    csv_path = f"{args.out}.csv"
    jsonl_path = f"{args.out}.jsonl"

    with open(csv_path, "w", newline="", encoding="utf-8") as cf, open(jsonl_path, "a", encoding="utf-8") as jf:
        writer = csv.DictWriter(cf, fieldnames=["hash","timestamp","status","summary"])
        writer.writeheader()

        for i, h in enumerate(items, 1):
            print(f"[{i}/{total}] {h[:16]}... ", end="", flush=True)
            ctx = {"hash": h, "timestamp": datetime.now(timezone.utc).isoformat()}
            try:
                resp = fetch_hash(api_key, h)
                ctx["result"] = resp
                ctx["status"] = "ok"
                stats = resp.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                positives = stats.get("malicious") if isinstance(stats, dict) else None
                ctx["summary"] = f"malicious={positives}" if positives is not None else ""
                print("ok")
            except requests.HTTPError as he:
                if he.response is not None and he.response.status_code == 429:
                    print("429 rate-limit; honoring Retry-After...", end="", flush=True)
                    safe_sleep_for_retry(he.response)
                    try:
                        resp = fetch_hash(api_key, h)
                        ctx["result"] = resp
                        ctx["status"] = "ok"
                        stats = resp.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        positives = stats.get("malicious") if isinstance(stats, dict) else None
                        ctx["summary"] = f"malicious={positives}" if positives is not None else ""
                        print("ok")
                    except Exception as e2:
                        ctx["status"] = "error"; ctx["error"] = str(e2); print("error ->", e2)
                else:
                    ctx["status"] = "error"; ctx["error"] = f"HTTP {he.response.status_code if he.response else ''} {he}"; print("error ->", ctx["error"])
            except Exception as e:
                ctx["status"] = "error"; ctx["error"] = str(e); print("error ->", e)

            jf.write(json.dumps(ctx, ensure_ascii=False) + "\n")
            writer.writerow({"hash": ctx.get("hash"), "timestamp": ctx.get("timestamp"), "status": ctx.get("status"), "summary": ctx.get("summary","")})
            if i < total:
                time.sleep(args.delay)

    print("Done. CSV:", csv_path, "JSONL:", jsonl_path)

if __name__ == "__main__":
    main()
