#!/usr/bin/env python3

import asyncio
import json
import struct
import os
import hashlib
from typing import Tuple, Dict, Any, Optional

HEADER_LEN_SIZE = 4  # 4-byte big-endian length for header


class ProtocolError(Exception):
    pass


async def read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data


async def read_frame(reader: asyncio.StreamReader) -> Tuple[Dict[str, Any], bytes]:
    """
    Frame format:
    - 4 bytes: big-endian unsigned int: header length (N)
    - N bytes: UTF-8 JSON header
    - payload: optional, length specified in header["size"]
    """
    header_len_bytes = await reader.readexactly(HEADER_LEN_SIZE)
    (header_len,) = struct.unpack("!I", header_len_bytes)
    if header_len > 10_000_000:
        raise ProtocolError("Unreasonable header length")
    header_bytes = await reader.readexactly(header_len)
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ProtocolError(f"Invalid JSON header: {e}") from e

    size = int(header.get("size", 0))
    payload = b""
    if size:
        payload = await reader.readexactly(size)
    return header, payload


async def write_frame(
    writer: asyncio.StreamWriter,
    header: Dict[str, Any],
    payload: Optional[bytes] = None,
) -> None:
    if payload is None:
        payload = b""
    header = dict(header)
    header["size"] = len(payload)
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    writer.write(struct.pack("!I", len(header_bytes)))
    writer.write(header_bytes)
    if payload:
        writer.write(payload)
    await writer.drain()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_fs_root(path: str) -> bool:
    """True if path is a filesystem root (POSIX '/' or Windows drive root)."""
    p = os.path.abspath(path)
    drive, tail = os.path.splitdrive(p)
    return p == os.path.sep or (bool(drive) and tail == os.path.sep)


def safe_join(base: str, *paths: str) -> str:
    """
    Strict join for the SERVER's storage paths (prevents traversal outside base).
    Keep this strict on the server side.
    """
    base = os.path.realpath(base)
    candidate = os.path.realpath(os.path.join(base, *paths))
    if not (candidate == base or candidate.startswith(base + os.sep)):
        raise ValueError("Path traversal detected")
    return candidate


def resolve_client_path(root: str, path: Optional[str]) -> str:
    """
    Lenient resolver for the CLIENT side:
    - If 'path' is absolute, return its realpath (allow full FS access).
    - If 'path' is relative or '.', resolve relative to 'root' (no traversal blocking).
    This function intentionally allows leaving 'root' when using '..' — to satisfy
    the “browse anywhere on the filesystem” requirement.
    """
    if not path or path == ".":
        return os.path.realpath(root)
    if os.path.isabs(path):
        return os.path.realpath(path)
    return os.path.realpath(os.path.join(root, path))
