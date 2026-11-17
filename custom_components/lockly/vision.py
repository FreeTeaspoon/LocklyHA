"""Vision Connect's CS2/PPCS transport, traced from Lockly Home 1.6.2.

Only the control channel is opened. No native SDK or phone process is needed.
Cloud lookup finds the hub's current UDP port, then the authenticated session
carries the same BLE frames used by the integration's other transports.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import reduce
import ipaddress
import socket
import struct
import time

from .api import crc8_lockly

# Shared application constants, not account or device credentials.
_P2P_KEY = b"U7iuNZEfje"
_CLOUD_HOSTS = ("3.223.181.96", "p2psg.lockly.com", "p2pau.lockly.com")
_TABLE = bytes.fromhex(
    "7c9ce84a13dedcb22f2123e4307b3d8cbc0b270c3cf79ae7087196009785efc11fc4dba1c2ebd901faba3b05b81587832872"
    "d18b5ad6da9358feaacc6e1bf0a388ab43c00db545384f502266207f075b14981d9ba72ab9a8cbf1fc4947063eb10e043a94"
    "5eee541134dd4df9ecc7c9e3781a6f706ba4bda95dd5f8e5bb26af4237d8e1020aae5f1cc573094e6924906d12b319ad748a"
    "2940f52dbea559e0f479d24bce8982488425c6912ba2fb8fe9a6b09e3f65f603312eac0f952c5ced39b7336c567eb4a0fd7a"
    "815351868d9f77ff6a80dfe2bf10d775645776f355cdd0c818e6364162cf99f2324c67606192cad3ea637d16b68ed46835c3"
    "529d46441e17"
)
_KEY_BYTES = bytes((sum(_P2P_KEY) & 255, -sum(_P2P_KEY) & 255,
                    sum(c // 3 for c in _P2P_KEY) & 255, reduce(int.__xor__, _P2P_KEY)))
_MAGIC = 1987479688
_MAX_MESSAGE = 65536
_WINDOW = 128


class VisionError(Exception):
    """The hub could not authenticate or carry a control frame."""


def is_vision_lock(lock: dict) -> bool:
    """Camera credentials select this path, even when hubid is empty."""
    return bool(lock.get("p2pdid") and lock.get("p2ppw"))


def encode_packet(data: bytes) -> bytes:
    """PPCS's application-key packet encoding; it is not account encryption."""
    out = bytearray()
    for value in data:
        previous = out[-1] if out else None
        index = (_KEY_BYTES[previous & 3] + previous) & 255 if previous is not None else _KEY_BYTES[0]
        out.append(value ^ _TABLE[index])
    return bytes(out)


def decode_packet(data: bytes) -> bytes:
    """Undo packet encoding using the preceding encoded byte."""
    out = bytearray()
    for i, value in enumerate(data):
        previous = data[i - 1] if i else None
        index = (_KEY_BYTES[previous & 3] + previous) & 255 if previous is not None else _KEY_BYTES[0]
        out.append(value ^ _TABLE[index])
    return bytes(out)


def pack_uid(uid: str) -> bytes:
    """Encode the SDK's 8-byte prefix, network-order number and 8-byte suffix."""
    try:
        prefix, serial, suffix = uid.split("-")
        if prefix != "LOCKLYV" or not serial.isascii() or not serial.isdigit():
            raise ValueError
        if not 1 <= len(suffix) <= 7 or not suffix.isascii() or not suffix.isalnum():
            raise ValueError
        return struct.pack("!8sI8s", prefix.encode(), int(serial), suffix.encode())
    except (ValueError, OverflowError, struct.error) as exc:
        raise VisionError("This Vision hub ID format is not supported") from exc


def pack_address(address: tuple[str, int]) -> bytes:
    """PPCS swaps sockaddr fields, including the already-network-order port."""
    host, port = address
    return struct.pack("!H", socket.AF_INET) + struct.pack("<H", port) + socket.inet_aton(host)[::-1] + bytes(8)


def unpack_address(data: bytes) -> tuple[str, int]:
    if len(data) != 16 or data[:2] != b"\x00\x02":
        raise VisionError("Invalid hub lookup address")
    host, port = socket.inet_ntoa(data[4:8][::-1]), int.from_bytes(data[2:4], "little")
    ip = ipaddress.ip_address(host)
    if not port or ip.is_unspecified or ip.is_loopback or ip.is_multicast or str(ip) == "255.255.255.255":
        raise VisionError("Invalid hub lookup endpoint")
    return host, port


def pack_control(command: int, payload: bytes) -> bytes:
    if len(payload) > _MAX_MESSAGE:
        raise VisionError("Control message is too large")
    return struct.pack("<6I", _MAGIC, len(payload), command, 0, 0, 0) + payload


def unpack_bypass(payload: bytes) -> bytes:
    """Read the short, medium or long passthrough reply, without padding."""
    if len(payload) not in (120, 172, 620, 1556):
        raise VisionError("Invalid passthrough response length")
    source, _channel, _kind, size = struct.unpack_from("<4I", payload)
    result = struct.unpack_from("<i", payload, len(payload) - 4)[0]
    if source not in (0, 1, 2) or size < 9 or size > len(payload) - 20:
        raise VisionError("Invalid passthrough response fields")
    if result:
        raise VisionError(f"Vision hub refused passthrough, code {result}")
    frame = payload[16:16 + size]
    # A CRC-valid BLE response is checked before it reaches any decryptor.
    if frame[:4] != b"\xa1\xb2\xc3\xd4" or int.from_bytes(frame[4:6], "little") != len(frame):
        raise VisionError("Invalid BLE response framing")
    if crc8_lockly(frame[:-1]) != frame[-1]:
        raise VisionError("Invalid BLE response checksum")
    return frame


class VisionClient(asyncio.DatagramProtocol):
    """One bounded, ordered control session per hub.

    Retransmission uses the same DRW sequence, so the hub deduplicates a lost
    datagram. An application command is never replayed after a reconnect.
    """

    def __init__(self, uid: str, password: str, on_frame: Callable[[bytes], None] | None = None) -> None:
        self._uid = pack_uid(uid)
        self._password = password.encode()
        if not self._password or len(self._password) > 72:
            raise VisionError("Invalid Vision hub credential length")
        self._on_frame = on_frame
        self._lock = asyncio.Lock()
        self._transport: asyncio.DatagramTransport | None = None
        self._peer: tuple[str, int] | None = None
        self._servers: set[tuple[str, int]] = set()
        self._targets: set[tuple[str, int]] = set()
        self._ready: asyncio.Future | None = None
        self._reply: asyncio.Future | None = None
        self._expected: set[int] = set()
        self._maintenance: asyncio.Task | None = None
        self._pending: dict[int, tuple[bytes, float, int]] = {}
        self._sequence = 0
        self._rx_sequence = 0
        self._chunks: dict[int, bytes] = {}
        self._stream = bytearray()
        self._last_received = 0.0
        self._authenticated = False
        self._closed = False
        self._local_address = "0.0.0.0"
        self._lost: asyncio.Future | None = None

    @property
    def connected(self) -> bool:
        return self._authenticated and self._transport is not None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        self._lost = asyncio.get_running_loop().create_future()

    def error_received(self, exc: Exception) -> None:
        # A failed WAN punch must not abort a successful LAN route.
        pass

    def connection_lost(self, exc: Exception | None) -> None:
        self._fail("Vision connection closed")
        if self._lost is not None and not self._lost.done():
            self._lost.set_result(None)

    def _send(self, kind: int, payload: bytes = b"", peer: tuple[str, int] | None = None) -> None:
        target = peer or self._peer
        if self._transport is None or target is None:
            raise VisionError("Vision connection is closed")
        self._transport.sendto(encode_packet(struct.pack("!BBH", 0xF1, kind, len(payload)) + payload), target)

    def _fail(self, reason: str) -> None:
        self._authenticated = False
        for future in (self._ready, self._reply):
            if future is not None and not future.done():
                future.set_exception(VisionError(reason))
        if self._transport is not None:
            transport, self._transport = self._transport, None
            transport.close()
        self._pending.clear()

    def datagram_received(self, raw: bytes, address: tuple[str, int]) -> None:
        if len(raw) < 4 or len(raw) > 4096:
            return
        packet = decode_packet(raw)
        if packet[0] != 0xF1 or int.from_bytes(packet[2:4], "big") != len(packet) - 4:
            return
        kind, payload = packet[1], packet[4:]
        try:
            if self._peer is None:
                self._handshake(kind, payload, address)
                return
            if address != self._peer:
                return
            self._last_received = time.monotonic()
            if kind == 0xE0:
                self._send(0xE1)
            elif kind == 0xF0:
                self._fail("Vision hub closed the session")
            elif kind == 0xD1:
                if len(payload) >= 4 and payload[:2] == b"\xd1\x00":
                    count = int.from_bytes(payload[2:4], "big")
                    if len(payload) == 4 + count * 2:
                        for offset in range(4, len(payload), 2):
                            self._pending.pop(int.from_bytes(payload[offset:offset + 2], "big"), None)
            elif kind == 0xD0:
                self._receive_data(payload)
        except (VisionError, ValueError, struct.error):
            self._fail("Invalid Vision control response")

    def _handshake(self, kind: int, payload: bytes, address: tuple[str, int]) -> None:
        if address in self._servers:
            if kind == 1 and len(payload) == 16:
                local = self._transport.get_extra_info("sockname")
                local = (self._local_address, local[1])
                self._send(0x20, self._uid + pack_address(local), address)
            elif kind == 0x40 and len(payload) == 16:
                target = unpack_address(payload)
                if len(self._targets) < 8 or target in self._targets:
                    self._targets.add(target)
                    self._send(0x41, self._uid, target)
            return
        if address not in self._targets or payload != self._uid:
            return
        if kind in (0x41, 0x42):
            self._send(0x42, self._uid, address)
            if kind == 0x42:
                self._peer = address
                self._last_received = time.monotonic()
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(None)

    def _receive_data(self, payload: bytes) -> None:
        if len(payload) < 4 or payload[0] != 0xD1:
            return
        channel, sequence = payload[1], int.from_bytes(payload[2:4], "big")
        if channel != 0:
            return
        self._send(0xD1, payload[:2] + b"\x00\x01" + payload[2:4])
        distance = (sequence - self._rx_sequence) & 0xFFFF
        if distance >= _WINDOW:
            return  # Old duplicate or outside the bounded reorder window.
        self._chunks.setdefault(sequence, payload[4:])
        while self._rx_sequence in self._chunks:
            self._stream.extend(self._chunks.pop(self._rx_sequence))
            self._rx_sequence = (self._rx_sequence + 1) & 0xFFFF
        if len(self._stream) > _MAX_MESSAGE + 24:
            raise VisionError("Vision receive buffer exceeded")
        while len(self._stream) >= 24:
            magic, size, command, *_ = struct.unpack_from("<6I", self._stream)
            if magic != _MAGIC or size > _MAX_MESSAGE:
                raise VisionError("Invalid Vision message header")
            if len(self._stream) < 24 + size:
                break
            body = bytes(self._stream[24:24 + size])
            del self._stream[:24 + size]
            if command in self._expected and self._reply is not None and not self._reply.done():
                self._reply.set_result(body)
            elif command in (33117, 33119, 33121) and self._authenticated and self._on_frame:
                self._on_frame(unpack_bypass(body))

    async def _maintain(self) -> None:
        last_alive = 0.0
        try:
            while self._transport is not None:
                await asyncio.sleep(0.25)
                now = time.monotonic()
                if self._peer is None:
                    continue
                if now - self._last_received > 25:
                    self._fail("Vision hub stopped answering")
                    return
                if now - last_alive > 5:
                    self._send(0xE0)
                    last_alive = now
                for sequence, (data, sent, attempts) in list(self._pending.items()):
                    if now - sent >= 0.75:
                        if attempts >= 5:
                            self._fail("Vision datagram was not acknowledged")
                            return
                        self._send(0xD0, data)
                        self._pending[sequence] = (data, now, attempts + 1)
        except asyncio.CancelledError:
            pass

    async def _connect(self) -> None:
        if self._closed:
            raise VisionError("Vision client has been shut down")
        if self.connected:
            return
        await self._disconnect()
        loop = asyncio.get_running_loop()
        self._peer = None
        self._targets.clear()
        self._sequence = self._rx_sequence = 0
        self._chunks.clear()
        self._stream.clear()
        resolutions = await asyncio.gather(*(
            loop.getaddrinfo(host, 32100, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            for host in _CLOUD_HOSTS
        ), return_exceptions=True)
        self._servers = {result[0][4] for result in resolutions if isinstance(result, list) and result}
        if not self._servers:
            raise VisionError("Could not resolve Vision lookup servers")
        def outgoing_address() -> str:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect(next(iter(self._servers)))
                return route.getsockname()[0]

        self._local_address = await loop.run_in_executor(None, outgoing_address)
        self._ready = loop.create_future()
        try:
            await loop.create_datagram_endpoint(lambda: self, local_addr=("0.0.0.0", 0), family=socket.AF_INET)
            self._maintenance = asyncio.create_task(self._maintain())
            for _ in range(10):
                for server in self._servers:
                    self._send(0, peer=server)
                try:
                    await asyncio.wait_for(asyncio.shield(self._ready), 1.0)
                    break
                except TimeoutError:
                    continue
            else:
                raise VisionError("Vision hub lookup or connection timed out")
            response = await self._request(16, self._password.ljust(72, b"\x00"), {16})
            if len(response) < 20 or struct.unpack_from("<i", response)[0]:
                raise VisionError("Vision hub rejected its stored credential")
            self._authenticated = True
        except BaseException:
            await self._disconnect()
            raise
        finally:
            if self._ready is not None:
                if not self._ready.done():
                    self._ready.cancel()
                elif not self._ready.cancelled():
                    self._ready.exception()
                self._ready = None

    async def _request(self, command: int, payload: bytes, expected: set[int]) -> bytes:
        loop = asyncio.get_running_loop()
        self._reply = loop.create_future()
        self._expected = expected
        message = pack_control(command, payload)
        try:
            for offset in range(0, len(message), 1024):
                sequence = self._sequence
                self._sequence = (sequence + 1) & 0xFFFF
                data = b"\xd1\x00" + struct.pack("!H", sequence) + message[offset:offset + 1024]
                self._pending[sequence] = (data, time.monotonic(), 1)
                self._send(0xD0, data)
            return await asyncio.wait_for(self._reply, 12)
        except TimeoutError as exc:
            self._fail("Vision control request timed out")
            raise VisionError("Vision control request timed out") from exc
        except asyncio.CancelledError:
            self._fail("Vision control request cancelled")
            raise
        finally:
            self._expected = set()
            self._reply = None

    async def async_exchange(self, frame: bytes, channel: int = 0) -> bytes:
        """Send one BLE frame. Never automatically replay it after failure."""
        if not 1 <= len(frame) <= 100:
            raise VisionError("Vision short control frame exceeds 100 bytes")
        async with self._lock:
            await self._connect()
            payload = struct.pack("<4I", 2, channel, 0, len(frame)) + frame.ljust(100, b"\x00")
            response = await self._request(33118, payload, {33117, 33119, 33121})
            return unpack_bypass(response)

    async def async_connect(self) -> None:
        """Restore hub notifications without sending a BLE query to the lock."""
        async with self._lock:
            await self._connect()

    async def _disconnect(self) -> None:
        if self._maintenance is not None:
            self._maintenance.cancel()
            await asyncio.gather(self._maintenance, return_exceptions=True)
            self._maintenance = None
        if self._transport is not None:
            if self._peer is not None:
                self._send(0xF0)
            self._transport.close()
            self._transport = None
        # connection_lost belongs to the old socket, and must run before a new
        # socket is assigned to this protocol object.
        if self._lost is not None and not self._lost.done():
            await self._lost
        self._authenticated = False
        self._pending.clear()

    async def async_close(self) -> None:
        self._closed = True
        self._fail("Vision client shut down")
        await self._disconnect()
