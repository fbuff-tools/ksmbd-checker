# KSMBD exposure checker (ZDI-CAN-33774, ZDI-CAN-33549)

Check whether a Linux server runs **KSMBD**, the kernel's built-in SMB3 file server, and is exposed to the two critical flaws disclosed before any fix existed: **ZDI-CAN-33774** and **ZDI-CAN-33549** (CVSS 9.0).

**Paste the command output in the browser instead:** https://fbuff.com/tools/ksmbd-checker/ (runs locally, nothing is uploaded)

## What happened

On October 21 and 22, 2026, Trend Micro's Zero Day Initiative sent six Linux kernel bug reports to public mailing lists before fixes existed. Two are in KSMBD:

| ID | What | Who can reach it |
|---|---|---|
| ZDI-CAN-33774 | Race condition in protocol selection | Anyone who can reach TCP 445 on a server running KSMBD, **no login needed** |
| ZDI-CAN-33549 | Integer underflow in the SMB Direct (RDMA) path | Needs an RDMA interface (hardware or `rxe`), a writable share and SMB Direct, which is off by default |

As of October 23, 2026: no mainline fix for ZDI-CAN-33774, a fix for ZDI-CAN-33549 submitted for a later release, no CVE numbers yet, no attacks reported in the wild.

## Who is affected

Only servers where KSMBD is running. It has been in the kernel since Linux 5.15 but stays off unless ksmbd-tools is installed and the `ksmbd` service is started. **Samba is not affected.** Red Hat Enterprise Linux does not ship KSMBD. Check NAS boxes and appliances too: some use KSMBD.

## Check from the command line

```sh
curl -fsSLO https://raw.githubusercontent.com/fbuff-tools/ksmbd-checker/main/check.sh
sh check.sh
```

The script reads `uname -r`, `lsmod`, `systemctl is-active ksmbd`, `ss -ltn 'sport = :445'` and `/sys/class/infiniband`, prints a verdict and exits with 1 if KSMBD is running. It only reads; nothing is sent or changed. Run it on the host, not inside a container.

## Turn KSMBD off until a fix ships

```sh
sudo systemctl disable --now ksmbd
sudo modprobe -r ksmbd
echo 'install ksmbd /bin/false' | sudo tee /etc/modprobe.d/disable-ksmbd.conf
```

If KSMBD must stay: allow TCP 445 only from trusted hosts, never from the internet, remove guest shares, keep SMB Direct off unless you need RDMA, and install your distribution's fixed kernel when it is released.

## Sources

- [Cyber Kendra: Linux KSMBD RCE flaws disclosed unpatched by Trend Micro ZDI](https://www.cyberkendra.com/2026/10/linux-ksmbd-rce-flaws-zdi-public-mailing-list.html)
- [Threat Landscape: Unpatched KSMBD RCE flaws ZDI-CAN-33774 and ZDI-CAN-33549](https://threatlandscape.io/blog/ksmbd-zdi-can-33774-33549-unpatched-rce)
- [Hardware Busters: Linux kernel vulnerabilities hit the public mailing list before the fixes](https://hwbusters.com/news/linux-kernel-vulnerabilities-hit-the-public-mailing-list-before-the-fixes-two-of-them-rated-cvss-9-0/)

Related: [HTTP2Shell checker](https://github.com/fbuff-tools/http2shell-checker), [PHP2Shell checker](https://github.com/fbuff-tools/php2shell-checker).

Information as of October 25, 2026. This page will add CVE numbers and fixed kernels when they are published. MIT license. Made by [fbuff](https://fbuff.com).
