#!/usr/bin/env -S uv run -s
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "httpx[http2]>=0.27.2",
#   "zstandard>=0.23.0",
# ]
# ///
"""
Fetch and maintain the latest PCAPs.

Now converts decoded .pcapng → .pcap via `editcap -F pcap`.

Usage:
  chmod +x ./pcap_fetcher.py
  ./pcap_fetcher.py --out ./pcaps --token "$AUTH_TOKEN" [--base-url https://icc-test.ierae-zero.day]
"""

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

import httpx
import zstandard as zstd
import shutil
import subprocess

GET_PCAPS_PATH = "/core.v1.FrontendService/GetPcaps"
# We key by the 14-digit timestamp.
FNAME_TS_RE = re.compile(r"(?P<ts>\d{14})\.pcap(?:ng)?(?:\.zst)?$", re.IGNORECASE)

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True, type=Path, help="Output folder for final .pcap files")
    p.add_argument("--token", required=True, help="Bearer token")
    p.add_argument("--base-url", default="https://icc-test.ierae-zero.day", help="API origin")
    p.add_argument("--page-size", type=int, default=10)
    p.add_argument("--max-pages", type=int, default=1000)
    p.add_argument("--editcap", default="editcap", help="Path to editcap binary")
    return p.parse_args()

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def existing_timestamps(out_dir: Path) -> Set[str]:
    """Recognize existing final .pcap files by 14-digit timestamp in filename."""
    ts: Set[str] = set()
    for p in out_dir.glob("*.pcap"):
        m = FNAME_TS_RE.search(p.name)
        if m:
            ts.add(m.group("ts"))
    return ts

def extract_ts_from_url(url: str) -> Optional[str]:
    base = url.split("?", 1)[0].rsplit("/", 1)[-1]
    m = FNAME_TS_RE.search(base)
    return m.group("ts") if m else None

def final_name_from_url(url: str) -> Optional[str]:
    """
    Input example: 20251018101400.pcapng.zst → output final name: 20251018101400.pcap
    """
    base = url.split("?", 1)[0].rsplit("/", 1)[-1]
    if not base.lower().endswith(".pcapng.zst"):
        return None
    return base[:-len(".pcapng.zst")] + ".pcap"

def fetch_page(client: httpx.Client, base_url: str, token: str, page_size: int, page_token: Optional[str]) -> Dict:
    payload: Dict[str, object] = {"pageSize": page_size}
    if page_token:
        payload["pageToken"] = page_token
    r = client.post(
        base_url + GET_PCAPS_PATH,
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
        timeout=30.0,
    )
    r.raise_for_status()
    return r.json()

def download_decode_convert(client: httpx.Client, url: str, final_pcap_path: Path, editcap_path: str) -> None:
    """
    Steps:
      - Download .zst → tmp
      - Decompress to .pcapng → tmp
      - Convert with `editcap -F pcap tmp.pcapng tmp.pcap`
      - Atomic move tmp.pcap → final_pcap_path
      - .zst and .pcapng are discarded
    """
    if not shutil.which(editcap_path):
        raise RuntimeError(f"`editcap` not found at '{editcap_path}'. Install Wireshark/tshark suite or provide --editcap path.")

    ensure_dir(final_pcap_path.parent)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        tmp_zst = td / "download.pcapng.zst"
        tmp_pcapng = td / "decoded.pcapng"
        tmp_pcap = td / "converted.pcap"

        # Download .zst
        with client.stream("GET", url, timeout=None) as resp:
            resp.raise_for_status()
            with tmp_zst.open("wb") as f:
                for chunk in resp.iter_bytes():
                    if chunk:
                        f.write(chunk)

        # Decompress to .pcapng
        dctx = zstd.ZstdDecompressor()
        with tmp_zst.open("rb") as src, tmp_pcapng.open("wb") as dst:
            dctx.copy_stream(src, dst)

        # Convert pcapng → pcap
        subprocess.run(
            [editcap_path, "-F", "pcap", str(tmp_pcapng), str(tmp_pcap)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Atomic move to final destination
        tmp_pcap.replace(final_pcap_path)

def process(args: argparse.Namespace) -> None:
    ensure_dir(args.out)
    have = existing_timestamps(args.out)

    page_token: Optional[str] = None
    pages = 0

    with httpx.Client(http2=True) as client:
        while True:
            pages += 1
            if pages > args.max_pages:
                print(f"Hit --max-pages={args.max_pages}. Stopping.", file=sys.stderr)
                break

            data = fetch_page(client, args.base_url, args.token, args.page_size, page_token)
            pcaps: Iterable[Dict] = data.get("pcaps", []) or []
            if not pcaps:
                print("No pcaps returned. Done.")
                break

            oldest_ts_on_page: Optional[str] = None

            for item in pcaps:
                url: str = item["downloadUrl"]
                ts = extract_ts_from_url(url)
                final_name = final_name_from_url(url)  # .pcap output name
                if ts is None or final_name is None:
                    print(f"Skip entry with unrecognized filename in URL: {url}", file=sys.stderr)
                    continue

                if oldest_ts_on_page is None or ts < oldest_ts_on_page:
                    oldest_ts_on_page = ts

                final_path = args.out / final_name
                if ts in have and final_path.exists():
                    print(f"Have {final_path.name}")
                    continue

                print(f"Downloading + converting {final_name} …")
                try:
                    download_decode_convert(client, url, final_path, args.editcap)
                except subprocess.CalledProcessError as e:
                    print(f"editcap failed for {final_name}: {e.stderr.decode(errors='ignore')}", file=sys.stderr)
                    continue
                except Exception as e:
                    print(f"Failed {final_name}: {e}", file=sys.stderr)
                    continue

                have.add(ts)
                print(f"Wrote {final_path.name}")

            # Stop if the oldest entry on this page already exists locally.
            if oldest_ts_on_page and oldest_ts_on_page in have:
                print(f"Oldest on page {oldest_ts_on_page} present. Done.")
                break

            page_token = data.get("nextPageToken")
            if not page_token:
                print("No nextPageToken. Done.")
                break

            print(f"Paginating… nextPageToken={page_token}")

def main() -> None:
    args = parse_args()
    try:
        process(args)
    except httpx.HTTPStatusError as e:
        print(f"HTTP error: {e.response.status_code} {e.request.url}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)

if __name__ == "__main__":
    main()

