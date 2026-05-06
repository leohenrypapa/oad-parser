#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: scripts/inspect_pcap.sh PATH_TO_PCAP"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ $# -ne 1 ]; then
  usage
  exit 2
fi

pcap="$1"

if [ ! -f "$pcap" ]; then
  echo "ERROR: file not found: $pcap" >&2
  exit 1
fi

echo "file: $pcap"
du -h "$pcap"

if command -v sha256sum >/dev/null 2>&1; then
  echo
  echo "== sha256 =="
  sha256sum "$pcap"
fi

if command -v capinfos >/dev/null 2>&1; then
  echo
  echo "== capinfos =="
  capinfos "$pcap" || true
fi

if command -v tshark >/dev/null 2>&1; then
  echo
  echo "== tshark protocol hierarchy =="
  tshark -r "$pcap" -q -z io,phs || true

  echo
  echo "== first 25 packets =="
  tshark -r "$pcap" -c 25 -T fields \
    -e frame.number \
    -e frame.time_epoch \
    -e eth.src \
    -e eth.dst \
    -e ip.src \
    -e ip.dst \
    -e udp.srcport \
    -e udp.dstport \
    -e frame.len || true
else
  echo
  echo "WARN: tshark not found. Skipping Wireshark CLI inspection."
fi

if python3 -m oad_parser --help 2>&1 | grep -q "inspect-pcap"; then
  echo
  echo "== oad_parser inspect-pcap =="
  python3 -m oad_parser inspect-pcap "$pcap"
else
  echo
  echo "WARN: current CLI does not expose inspect-pcap. Skipping parser inspection."
fi
