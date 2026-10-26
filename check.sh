#!/bin/sh
# KSMBD exposure check for ZDI-CAN-33774 and ZDI-CAN-33549 (disclosed October 21-22, 2026, CVSS 9.0, no fix yet).
# It only reads the kernel version, loaded modules, services, listening ports and RDMA devices:
# nothing is sent anywhere and nothing is changed.
#
# Usage: sh check.sh
# Exit code: 0 = not exposed, 1 = KSMBD is running, 2 = could not tell.

kernel=$(uname -r)
echo "Kernel: $kernel"

loaded=no
if lsmod 2>/dev/null | grep -q '^ksmbd '; then loaded=yes; fi
echo "ksmbd module loaded: $loaded"

active=no
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ksmbd 2>/dev/null; then active=yes; fi
echo "ksmbd service active: $active"

port=unknown
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 'sport = :445' 2>/dev/null | grep -q LISTEN; then port=yes; else port=no; fi
fi
echo "Listening on TCP 445: $port"

rdma=no
if [ -d /sys/class/infiniband ] && [ -n "$(ls -A /sys/class/infiniband 2>/dev/null)" ]; then rdma=yes; fi
echo "RDMA devices: $rdma"

if [ "$loaded" = yes ] || [ "$active" = yes ]; then
  if [ "$port" = no ]; then
    echo "Verdict: KSMBD IS RUNNING (nothing listens on 445 right now). Keep it unreachable or turn it off."
  else
    echo "Verdict: EXPOSED. KSMBD is running; ZDI-CAN-33774 needs no login. Turn it off or block TCP 445."
  fi
  [ "$rdma" = yes ] && echo "Also: RDMA devices present, so ZDI-CAN-33549 (SMB Direct) may apply. Keep SMB Direct off."
  echo "To turn KSMBD off:"
  echo "  sudo systemctl disable --now ksmbd"
  echo "  sudo modprobe -r ksmbd"
  echo "  echo 'install ksmbd /bin/false' | sudo tee /etc/modprobe.d/disable-ksmbd.conf"
  exit 1
fi

if ! command -v lsmod >/dev/null 2>&1; then
  echo "Verdict: UNKNOWN (lsmod not available). Check from the host, not from inside a container."
  exit 2
fi
echo "Verdict: not exposed (KSMBD is not running). Samba is a separate program and is not affected."
exit 0
