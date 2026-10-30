# KSMBD exposure checker (ZDI-CAN-33774, ZDI-CAN-33549)

Understand and check the two critical flaws in **KSMBD**, the Linux kernel's built-in SMB3 file server, that were posted publicly before any released kernel fixed them: **ZDI-CAN-33774** and **ZDI-CAN-33549** (CVSS 9.0, found by Hyeontae Lee, reported through Trend Micro's Zero Day Initiative on October 21-22, 2026).

**Paste the command output in the browser instead:** https://fbuff.com/tools/ksmbd-checker/ (runs locally, nothing is uploaded)

## What causes ZDI-CAN-33774: the server switches rulebooks mid-conversation

An SMB connection starts with a negotiation: client and server agree on SMB1 or SMB2/3, and KSMBD sets the connection's handler table (`conn->ops`) to match.

The bug is a race. KSMBD's receive thread keeps reading new messages while a worker is still handling the negotiation. If an attacker sends, in one TCP write, a burst of SMB1 messages followed by an SMB2 message, the SMB2 message can make `ksmbd_init_smb_server()` replace `conn->ops` while a worker is still processing an earlier, shorter SMB1 message. The worker then reads that short message with SMB2 handlers that expect a longer one and goes past its end.

Think of a translator who switches from French to German halfway through a sentence and keeps reading words that aren't there.

- **No login and no share needed:** anyone who can reach TCP 445 can try.
- **Public proof of concept:** leaks 28 bytes of kernel memory per attempt and can crash the server. ZDI rates it as remote code execution; a write past the buffer needs share access.
- **Fix:** commit `68f410faedaf`, "ksmbd: wait for negotiation before receiving another PDU", makes `queue_ksmbd_work()` hold further messages until negotiation is done. It is in the KSMBD development tree but **not in a released kernel** yet.

## What causes ZDI-CAN-33549: a counter that rolls over

SMB Direct moves file data over RDMA. The client describes its memory buffers with descriptors, each with a length. In `smbdirect_connection_rdma_xmit()`, if the first descriptor claims to be longer than the data actually sent, KSMBD trims it and sets the remaining length to zero, then subtracts the original, untrimmed length from that zero. The unsigned counter wraps to a huge number, like an odometer rolling back from 000000 to 999999, and a later memory copy writes past its buffer (up to about 8 KB, per Sysdig).

- **Needs:** an RDMA interface (hardware or the `rxe` software driver), SMB Direct negotiated, and a writable share.
- **Fix:** patches posted on October 23 ("smb: smbdirect: fix buffer length underflow in RDMA transfers" and a larger SMB Direct series), not merged yet.

## Who is affected

Only servers where KSMBD is running. It has been in the kernel since Linux 5.15 but stays off unless ksmbd-tools is installed and the `ksmbd` service is started. **Samba is not affected** (separate user-space code). Red Hat Enterprise Linux doesn't ship KSMBD, AlmaLinux and CloudLinux 9-10 kernels don't build it, and most desktops never load it. Check NAS boxes and appliances: some use KSMBD for speed.

## Status (October 30, 2026)

| | ZDI-CAN-33774 | ZDI-CAN-33549 |
|---|---|---|
| Login needed | No | Yes, a writable share |
| Fix | `68f410faedaf` in the KSMBD tree, not released | Patches posted, not merged |
| CVE | Not yet (assigned once a stable kernel has the fix) | Not yet |
| Public exploit | Memory leak and crash, no code execution | Crash in lab tests |
| Attacks seen | None reported | None reported |

## Check from the command line

```sh
curl -fsSLO https://raw.githubusercontent.com/fbuff-tools/ksmbd-checker/main/check.sh
sh check.sh
```

The script reads `uname -r`, `lsmod`, `systemctl is-active ksmbd`, `ss -ltn 'sport = :445'` and `/sys/class/infiniband`, prints a verdict and exits with 1 if KSMBD is running. It only reads; nothing is sent or changed. Run it on the host, not inside a container.

## Ways to protect a server

1. **Turn KSMBD off** if you don't need it (Samba can usually serve the same shares):
   ```sh
   sudo systemctl disable --now ksmbd
   sudo modprobe -r ksmbd
   echo 'install ksmbd /bin/false' | sudo tee /etc/modprobe.d/disable-ksmbd.conf
   ```
2. **If it must stay, limit who can reach it.** Allow TCP 445 only from trusted hosts, never from the internet: the only control that covers ZDI-CAN-33774, which needs no login. Remove guest shares.
3. **Keep SMB Direct and RDMA off** unless you rely on them; that closes ZDI-CAN-33549.
4. **Watch:** bursts of connections to port 445 that end in abrupt disconnects, and kernel oops/panic messages mentioning `ksmbd` or `fs/smb/server` (`journalctl -k`). Neither alone proves an attack.
5. **Install the fixed kernel** from your distribution as soon as it is released.

## Sources

- [Ostorlab: Linux KSMBD pre-auth flaw ZDI-CAN-33774](https://blog.ostorlab.co/linux-ksmbd-preauth-rce-zdi-can-33774.html)
- [Threat Landscape: Unpatched KSMBD RCE flaws ZDI-CAN-33774 and ZDI-CAN-33549](https://threatlandscape.io/blog/ksmbd-zdi-can-33774-33549-unpatched-rce)
- [Sysdig: Detecting and mitigating ZDI-CAN-33367 and five other Linux flaws](https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws)
- [Cyber Kendra: Linux KSMBD RCE flaws disclosed unpatched by Trend Micro ZDI](https://www.cyberkendra.com/2026/10/linux-ksmbd-rce-flaws-zdi-public-mailing-list.html)

Related: [CVE-2026-98432 checker](https://github.com/fbuff-tools/cve-2026-98432-checker) (Linux TCP), [HTTP2Shell checker](https://github.com/fbuff-tools/http2shell-checker), [PHP2Shell checker](https://github.com/fbuff-tools/php2shell-checker).

Information as of October 30, 2026. This page will add CVE numbers and fixed kernels when they are published. MIT license. Made by [fbuff](https://fbuff.com).
